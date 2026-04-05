"""
Bulkhead Model Evaluation Script.

Evaluates a trained model on a test set and reports per-entity metrics.

Usage:
    python evaluate.py --model ../models/pii-small/pytorch --dataset ai4privacy/pii-masking-400k
"""

import argparse
import json
from pathlib import Path
from collections import defaultdict

import numpy as np
from datasets import load_dataset
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    pipeline,
)
import evaluate as hf_evaluate


def main():
    parser = argparse.ArgumentParser(description="Evaluate Bulkhead PII model")
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to trained model directory",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="ai4privacy/pii-masking-400k",
        help="Dataset to evaluate on",
    )
    parser.add_argument(
        "--split",
        type=str,
        default="test",
        help="Dataset split to evaluate",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output path for evaluation report JSON",
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default=None,
        help="Baseline model to compare against (e.g., the pre-trained model)",
    )
    args = parser.parse_args()

    model_path = Path(args.model)

    print(f"Loading model: {model_path}")
    tokenizer = AutoTokenizer.from_pretrained(str(model_path))
    model = AutoModelForTokenClassification.from_pretrained(str(model_path))
    label_list = list(model.config.id2label.values())

    print(f"Loading dataset: {args.dataset} ({args.split})")
    dataset = load_dataset(args.dataset, split=args.split)

    # Run NER pipeline
    ner_pipeline = pipeline(
        "token-classification",
        model=model,
        tokenizer=tokenizer,
        aggregation_strategy="simple",
    )

    seqeval = hf_evaluate.load("seqeval")

    # Evaluate
    all_predictions = []
    all_labels = []

    for example in dataset:
        tokens = example["tokens"]
        ner_tags = example["ner_tags"]

        text = " ".join(tokens)
        predictions = ner_pipeline(text)

        # Map predictions back to token-level labels
        pred_labels = ["O"] * len(tokens)
        for pred in predictions:
            # Find which token(s) this prediction covers
            char_start = pred["start"]
            running_pos = 0
            for i, token in enumerate(tokens):
                token_start = text.index(token, running_pos)
                token_end = token_start + len(token)
                if token_start >= char_start and token_start < pred["end"]:
                    prefix = "B-" if token_start == char_start else "I-"
                    pred_labels[i] = prefix + pred["entity_group"]
                running_pos = token_end

        true_labels = [label_list[tag] for tag in ner_tags]
        all_predictions.append(pred_labels)
        all_labels.append(true_labels)

    # Compute metrics
    results = seqeval.compute(predictions=all_predictions, references=all_labels)

    # Per-entity breakdown
    report = {
        "model": str(model_path),
        "dataset": args.dataset,
        "split": args.split,
        "overall": {
            "precision": results["overall_precision"],
            "recall": results["overall_recall"],
            "f1": results["overall_f1"],
            "accuracy": results["overall_accuracy"],
        },
        "per_entity": {},
    }

    for key, value in results.items():
        if key.startswith("overall"):
            continue
        if isinstance(value, dict):
            report["per_entity"][key] = value

    # Print report
    print("\n=== Evaluation Report ===")
    print(f"Model: {model_path}")
    print(f"Dataset: {args.dataset} ({args.split})")
    print(f"\nOverall F1: {report['overall']['f1']:.4f}")
    print(f"Precision:  {report['overall']['precision']:.4f}")
    print(f"Recall:     {report['overall']['recall']:.4f}")
    print(f"Accuracy:   {report['overall']['accuracy']:.4f}")

    if report["per_entity"]:
        print(f"\nPer-entity F1:")
        for entity, metrics in sorted(report["per_entity"].items()):
            print(f"  {entity:30s} F1={metrics.get('f1', 0):.4f}  "
                  f"P={metrics.get('precision', 0):.4f}  "
                  f"R={metrics.get('recall', 0):.4f}  "
                  f"N={metrics.get('number', 0)}")

    # Save report
    output_path = args.output or str(model_path / "evaluation.json")
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {output_path}")


if __name__ == "__main__":
    main()
