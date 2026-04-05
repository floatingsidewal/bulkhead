"""
Bulkhead PII Model Training Script.

Fine-tunes a token-classification model for PII detection.
The trained model is exported to ONNX for use in the Bulkhead VS Code extension.

Usage:
    python train.py --config configs/pii-small.yaml

The contract between this training pipeline and the runtime is the ONNX model file.
Training produces it, runtime consumes it. They share nothing else.
"""

import argparse
import json
from pathlib import Path

import yaml
import numpy as np
from datasets import load_dataset
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    DataCollatorForTokenClassification,
    Trainer,
    TrainingArguments,
)
import evaluate


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Train Bulkhead PII model")
    parser.add_argument(
        "--config",
        type=str,
        default="configs/pii-small.yaml",
        help="Path to training config YAML",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading base model: {config['base_model']}")
    tokenizer = AutoTokenizer.from_pretrained(config["base_model"])
    model = AutoModelForTokenClassification.from_pretrained(config["base_model"])

    # Load dataset
    print(f"Loading dataset: {config['dataset']}")
    dataset = load_dataset(config["dataset"])

    # Get label list from model config
    label_list = list(model.config.id2label.values())
    print(f"Labels ({len(label_list)}): {label_list[:10]}...")

    # Tokenize and align labels
    def tokenize_and_align(examples):
        tokenized = tokenizer(
            examples["tokens"],
            truncation=True,
            is_split_into_words=True,
            max_length=config.get("max_seq_length", 512),
        )
        labels = []
        for i, label_ids in enumerate(examples["ner_tags"]):
            word_ids = tokenized.word_ids(batch_index=i)
            previous_word_idx = None
            label_row = []
            for word_idx in word_ids:
                if word_idx is None:
                    label_row.append(-100)
                elif word_idx != previous_word_idx:
                    label_row.append(label_ids[word_idx])
                else:
                    # For sub-word tokens, use I- tag if the word starts with B-
                    label_row.append(label_ids[word_idx])
                previous_word_idx = word_idx
            labels.append(label_row)
        tokenized["labels"] = labels
        return tokenized

    tokenized_dataset = dataset.map(
        tokenize_and_align,
        batched=True,
        remove_columns=dataset[config.get("train_split", "train")].column_names,
    )

    # Metrics
    seqeval = evaluate.load("seqeval")

    def compute_metrics(eval_pred):
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=2)

        true_predictions = [
            [label_list[p] for (p, l) in zip(pred, label) if l != -100]
            for pred, label in zip(predictions, labels)
        ]
        true_labels = [
            [label_list[l] for (p, l) in zip(pred, label) if l != -100]
            for pred, label in zip(predictions, labels)
        ]

        results = seqeval.compute(
            predictions=true_predictions, references=true_labels
        )
        return {
            "precision": results["overall_precision"],
            "recall": results["overall_recall"],
            "f1": results["overall_f1"],
            "accuracy": results["overall_accuracy"],
        }

    # Training arguments
    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=config.get("epochs", 3),
        per_device_train_batch_size=config.get("batch_size", 16),
        per_device_eval_batch_size=config.get("batch_size", 16),
        learning_rate=config.get("learning_rate", 5e-5),
        weight_decay=config.get("weight_decay", 0.01),
        warmup_ratio=config.get("warmup_ratio", 0.1),
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        push_to_hub=False,
        logging_steps=100,
    )

    data_collator = DataCollatorForTokenClassification(tokenizer=tokenizer)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset[config.get("train_split", "train")],
        eval_dataset=tokenized_dataset.get(config.get("eval_split", "validation")),
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )

    # Train
    print("Starting training...")
    trainer.train()

    # Save best model
    print(f"Saving model to {output_dir}")
    trainer.save_model(str(output_dir / "pytorch"))
    tokenizer.save_pretrained(str(output_dir / "pytorch"))

    # Save training metrics
    metrics = trainer.evaluate()
    with open(output_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Final metrics: {metrics}")

    print("Training complete. Run export.py to convert to ONNX.")


if __name__ == "__main__":
    main()
