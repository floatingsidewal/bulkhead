"""
Dataset preparation for Bulkhead PII model training.

Downloads public PII datasets, converts to HuggingFace format,
and splits into train/validation/test sets.

Usage:
    python data/prepare.py --dataset ai4privacy/pii-masking-400k --output data/prepared
"""

import argparse
from pathlib import Path

from datasets import load_dataset, DatasetDict


def main():
    parser = argparse.ArgumentParser(description="Prepare training datasets")
    parser.add_argument(
        "--dataset",
        type=str,
        default="ai4privacy/pii-masking-400k",
        help="HuggingFace dataset ID",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/prepared",
        help="Output directory for prepared dataset",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.1,
        help="Fraction of data to use for test set",
    )
    parser.add_argument(
        "--val-size",
        type=float,
        default=0.1,
        help="Fraction of data to use for validation set",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"Loading dataset: {args.dataset}")
    dataset = load_dataset(args.dataset)

    # If the dataset already has splits, use them
    if isinstance(dataset, DatasetDict) and "train" in dataset:
        print(f"Dataset already has splits: {list(dataset.keys())}")

        # Create test split if not present
        if "test" not in dataset:
            split = dataset["train"].train_test_split(test_size=args.test_size, seed=42)
            dataset["train"] = split["train"]
            dataset["test"] = split["test"]

        # Create validation split if not present
        if "validation" not in dataset:
            split = dataset["train"].train_test_split(test_size=args.val_size, seed=42)
            dataset["train"] = split["train"]
            dataset["validation"] = split["test"]
    else:
        # Single split — create train/val/test
        full = dataset if not isinstance(dataset, DatasetDict) else dataset["train"]
        split1 = full.train_test_split(test_size=args.test_size + args.val_size, seed=42)
        split2 = split1["test"].train_test_split(
            test_size=args.val_size / (args.test_size + args.val_size), seed=42
        )
        dataset = DatasetDict({
            "train": split1["train"],
            "test": split2["train"],
            "validation": split2["test"],
        })

    # Print stats
    for split_name, split_data in dataset.items():
        print(f"  {split_name}: {len(split_data)} examples")

    # Print label distribution
    if "ner_tags" in dataset["train"].features:
        from collections import Counter
        tag_counts = Counter()
        for example in dataset["train"]:
            tag_counts.update(example["ner_tags"])
        print(f"\nLabel distribution (train):")
        for tag, count in tag_counts.most_common(20):
            print(f"  {tag}: {count}")

    # Save
    dataset.save_to_disk(str(output_path))
    print(f"\nDataset saved to {output_path}")


if __name__ == "__main__":
    main()
