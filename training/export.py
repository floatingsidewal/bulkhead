"""
Bulkhead ONNX Export Script.

Converts a trained PyTorch model to ONNX format with optional quantization.
The exported model is the artifact consumed by the Bulkhead VS Code extension runtime.

Usage:
    python export.py --model ../models/pii-small/pytorch --output ../models/pii-small/onnx --quantize int8
"""

import argparse
import shutil
from pathlib import Path

from optimum.onnxruntime import ORTModelForTokenClassification, ORTQuantizer
from optimum.onnxruntime.configuration import AutoQuantizationConfig
from transformers import AutoTokenizer
import onnxruntime as ort
import numpy as np


def main():
    parser = argparse.ArgumentParser(description="Export Bulkhead model to ONNX")
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to trained PyTorch model directory",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output directory for ONNX model",
    )
    parser.add_argument(
        "--quantize",
        type=str,
        choices=["fp32", "fp16", "int8", "q4"],
        default="int8",
        help="Quantization level (default: int8)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        default=True,
        help="Validate ONNX output matches PyTorch output",
    )
    args = parser.parse_args()

    model_path = Path(args.model)
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"Loading model from {model_path}")
    tokenizer = AutoTokenizer.from_pretrained(str(model_path))

    # Export to ONNX
    print("Exporting to ONNX...")
    ort_model = ORTModelForTokenClassification.from_pretrained(
        str(model_path),
        export=True,
    )
    ort_model.save_pretrained(str(output_path / "fp32"))
    tokenizer.save_pretrained(str(output_path / "fp32"))
    print(f"FP32 model saved to {output_path / 'fp32'}")

    # Quantize if requested
    if args.quantize != "fp32":
        print(f"Quantizing to {args.quantize}...")

        if args.quantize == "int8":
            qconfig = AutoQuantizationConfig.avx512_vnni(
                is_static=False,
                per_channel=True,
            )
        elif args.quantize == "q4":
            qconfig = AutoQuantizationConfig.arm64(
                is_static=False,
                per_channel=True,
            )
        else:
            # fp16 - just copy for now (handled differently in ONNX Runtime)
            print("FP16 quantization: copying FP32 model (use dtype=fp16 at runtime)")
            shutil.copytree(output_path / "fp32", output_path / "fp16")
            return

        quantizer = ORTQuantizer.from_pretrained(ort_model)
        quantizer.quantize(
            save_dir=str(output_path / args.quantize),
            quantization_config=qconfig,
        )
        tokenizer.save_pretrained(str(output_path / args.quantize))
        print(f"Quantized model saved to {output_path / args.quantize}")

    # Validate
    if args.validate:
        print("Validating ONNX output...")
        validate_path = output_path / args.quantize if args.quantize != "fp32" else output_path / "fp32"
        validate_onnx_output(model_path, validate_path, tokenizer)

    # Print model size
    for onnx_file in output_path.rglob("*.onnx"):
        size_mb = onnx_file.stat().st_size / (1024 * 1024)
        print(f"  {onnx_file.relative_to(output_path)}: {size_mb:.1f} MB")

    print("\nExport complete. The ONNX model is ready for Bulkhead runtime.")


def validate_onnx_output(pytorch_path, onnx_path, tokenizer):
    """Verify that ONNX model produces similar outputs to PyTorch model."""
    from transformers import AutoModelForTokenClassification
    import torch

    # Load both models
    pt_model = AutoModelForTokenClassification.from_pretrained(str(pytorch_path))
    pt_model.eval()

    ort_model = ORTModelForTokenClassification.from_pretrained(str(onnx_path))

    # Test input
    test_text = "John Smith lives at 123 Main Street in Boston, MA 02101."
    inputs = tokenizer(test_text, return_tensors="pt")

    # PyTorch inference
    with torch.no_grad():
        pt_outputs = pt_model(**inputs)
    pt_logits = pt_outputs.logits.numpy()

    # ONNX inference
    ort_outputs = ort_model(**inputs)
    ort_logits = ort_outputs.logits.numpy()

    # Compare
    max_diff = np.max(np.abs(pt_logits - ort_logits))
    mean_diff = np.mean(np.abs(pt_logits - ort_logits))

    print(f"  Validation: max_diff={max_diff:.6f}, mean_diff={mean_diff:.6f}")
    if max_diff < 0.01:
        print("  ✓ ONNX output matches PyTorch output")
    else:
        print(f"  ⚠ Output difference is larger than expected (max_diff={max_diff:.6f})")


if __name__ == "__main__":
    main()
