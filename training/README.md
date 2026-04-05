# Bulkhead Training Pipeline

This directory contains the model training pipeline for Bulkhead's Layer 2 (BERT) classifier. It is **completely independent** from the runtime TypeScript code — they share nothing except the ONNX model artifact.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Prepare dataset
python data/prepare.py

# 3. Train
python train.py --config configs/pii-small.yaml

# 4. Evaluate
python evaluate.py --model ../models/pii-small/pytorch

# 5. Export to ONNX
python export.py --model ../models/pii-small/pytorch --output ../models/pii-small/onnx --quantize int8
```

## Architecture

```
training/          → Python (torch, transformers, optimum)
    ↓ produces
models/*.onnx      → ONNX model artifact
    ↓ consumed by
src/cascade/       → TypeScript (@huggingface/transformers, onnxruntime-node)
```

The **contract** between training and runtime is the ONNX model file. Training produces it, runtime loads and runs inference on it.

## Scripts

| Script | Purpose |
|--------|---------|
| `train.py` | Fine-tune a token-classification model |
| `evaluate.py` | Evaluate model quality (per-entity F1, precision, recall) |
| `export.py` | Convert PyTorch → ONNX with quantization (int8/q4) |
| `data/prepare.py` | Download and prepare training datasets |

## Configuration

Training configs live in `configs/`. Each YAML file specifies:
- Base model (HuggingFace model ID)
- Hyperparameters (epochs, batch size, learning rate)
- Dataset source
- Entity types to train on
- Quantization level for export

## Default Model

The default model is `gravitee-io/bert-small-pii-detection`:
- 28.5M parameters
- 24 PII entity types
- ~29 MB when quantized to INT8
- F1: 0.846

You can fine-tune this model on domain-specific data to improve accuracy for your use case.

## Adding Custom Entity Types

1. Annotate training data with your custom entity labels
2. Update the `entity_types` list in your config YAML
3. Train and evaluate
4. Export to ONNX

The runtime will automatically pick up new entity types from the model's label vocabulary.
