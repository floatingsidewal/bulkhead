# Architecture

## Overview

The cascading classifier is Bulkhead's core architectural contribution. The detection
patterns are ported from established open-source projects (Microsoft Presidio for PII,
HAI-Guardrails for secrets and injection -- see [ATTRIBUTION.md](../ATTRIBUTION.md)).
What Bulkhead adds is the three-layer cascade that routes detections through
progressively more expensive classifiers, the BERT worker thread integration, the LLM
disambiguation layer, and the deduplication logic that merges results across layers.

The cascade uses three detection layers that progressively trade speed for depth. Each layer acts as a filter that only escalates what it can't resolve with confidence.

```
┌─────────────────────────────────────────────────────┐
│                    Input Text                        │
└──────────────────────┬──────────────────────────────┘
                       │
         ┌─────────────▼──────────────┐
         │   Layer 1: Regex (sub-ms)  │  Always on. Catches structured PII,
         │   45+ patterns, checksums  │  secrets, injection patterns.
         │   confidence: 1.0          │  ~60-70% of detections stop here.
         │   disposition: "confirmed" │
         └─────────────┬──────────────┘
                       │ full text
         ┌─────────────▼──────────────┐
         │  Layer 2: BERT (20-50ms)   │  On-demand. Catches names, locations,
         │  28.5M params, INT8 ~29MB  │  organizations, contextual entities.
         │  Worker thread, lazy-load  │  Returns real confidence scores.
         │  ≥0.75 → "confirmed"       │
         │  <0.75 → "escalate"        │
         └─────────────┬──────────────┘
                       │ only escalated spans + context
         ┌─────────────▼──────────────┐
         │  Layer 3: LLM (500ms-2s)   │  Selective. Only sees ~5-10% of
         │  ±3 sentences context       │  detections — the genuinely ambiguous.
         │  Confirmed entities as      │  "Is 'Jordan' a person or country?"
         │  disambiguation signal      │
         │  → "confirmed"/"dismissed" │
         └────────────────────────────┘
```

## The Escalation Contract

Every detection carries provenance:

```typescript
interface Detection {
  entityType: string;        // "PERSON", "US_SSN", "AWS_ACCESS_KEY"
  text: string;              // the detected span
  score: number;             // 0-1 confidence
  source: "regex" | "bert" | "llm";
  context: string;           // surrounding text window (±150 chars)
  disposition: "confirmed" | "escalate" | "dismissed";
}
```

- **Regex** results always arrive with `confidence: 1.0`, `disposition: "confirmed"` — they're deterministic.
- **BERT** results carry a real confidence score. Above the threshold (default 0.75) → `confirmed`. Below → `escalate`.
- **LLM** only sees escalated items plus their context. Returns `confirmed` or `dismissed`.

## Why This Works

**Cost proportionality.** Regex catches 60-70% of PII by volume (structured data is the most common leak). BERT resolves most of the remainder. The LLM handles 5-10% — the genuinely ambiguous cases. Expensive inference runs on a tiny fraction of total work.

**Latency budget.** Regex is invisible (sub-ms on every keystroke, debounced). BERT runs on explicit "Deep Scan". LLM only fires on the handful of ambiguous spans, so the user sees "scanning... found 3 items needing review" rather than waiting for the whole document to process through an LLM.

**Auditability.** Each detection carries its provenance. When someone asks "why was this blocked?" you can say "regex matched SSN pattern with Luhn validation" or "BERT flagged a name at 0.92 confidence" rather than "the AI said so."

## Component Map

```
src/
├── types/index.ts              Core type definitions (Detection, Guard, etc.)
├── engine/engine.ts            GuardrailsEngine — orchestrates guards
├── cascade/
│   ├── cascade.ts              CascadeClassifier — the three-layer orchestrator
│   ├── bert-layer.ts           Main-thread BERT interface
│   ├── bert-worker.ts          Worker thread for BERT inference
│   └── llm-layer.ts            LLM disambiguation (Layer 3)
├── guards/
│   ├── base.guard.ts           Base class with shared logic
│   ├── pii.guard.ts            PII detection (45+ entity types)
│   ├── secret.guard.ts         Secret/credential detection
│   ├── injection.guard.ts      Prompt injection detection
│   └── leakage.guard.ts        System prompt leakage detection
├── patterns/
│   ├── pii/                    PII regex patterns by region
│   │   ├── generic.ts          Credit card, email, IBAN, IP, etc.
│   │   ├── us.ts               SSN, driver's license, passport, etc.
│   │   ├── uk.ts               NHS, NINO, postcode, etc.
│   │   ├── eu.ts               Spain, Italy, Poland, Finland, Sweden, Germany
│   │   ├── apac.ts             Singapore, Australia, India, Korea, Thailand, Nigeria
│   │   └── index.ts            Pattern registry
│   ├── secrets.ts              API key, token, credential patterns
│   └── injection.ts            Injection/leakage patterns and keywords
├── validators/
│   ├── checksums.ts            Luhn, IBAN mod-97, ABA, NPI, DEA, Shannon entropy
│   └── verhoeff.ts             Verhoeff algorithm (Aadhaar, Nigerian NIN)
├── vscode/
│   ├── extension.ts            VS Code extension entry point
│   ├── diagnostics.ts          Detection → VS Code diagnostic mapping
│   ├── code-actions.ts         Quick fixes (redact, dismiss)
│   ├── commands.ts             Command palette (scan, deep scan)
│   └── config.ts               Extension settings
└── extension.ts                Activation, lifecycle, auto-scan
```

## Training Pipeline (Independent)

The `training/` directory contains a separate Python pipeline for fine-tuning and exporting BERT models. It shares nothing with the runtime except the ONNX model artifact.

```
training/              → Python (torch, transformers, optimum)
    ↓ produces
models/*.onnx          → ONNX model artifact (the contract)
    ↓ consumed by
src/cascade/           → TypeScript (@huggingface/transformers)
```

See [training/README.md](../training/README.md) for details.

## VS Code Integration

```
Auto-scan (on edit, debounced 500ms)
  → engine.analyze() → Layer 1 only (regex)
  → Diagnostics shown inline

"Bulkhead: Scan File" command
  → engine.analyze() → Layer 1 only

"Bulkhead: Deep Scan" command
  → engine.deepScan() → Full cascade (Layer 1 + 2 + 3)
  → Progress indicator while BERT/LLM run
  → Diagnostics show source: [Bulkhead/regex], [Bulkhead/bert], [Bulkhead/llm]
  → Escalated items shown as info-level "needs review"

Code Actions (Quick Fixes)
  → "Redact EMAIL_ADDRESS" → replaces with [REDACTED-EMAIL_ADDRESS]
  → "Dismiss this warning"
```

## Context Window (Layer 3)

When BERT flags an ambiguous span, the LLM receives:

1. **±3 sentences** around the flagged span
2. **The BERT suggestion** (entity type + confidence)
3. **Confirmed detections** from the same document as metadata

This gives the LLM strong disambiguation signal without sending the entire document. Example prompt:

```
Context: "Alice and Jordan went to the store yesterday. They bought groceries."
Span: "Jordan"
BERT suggested: PERSON (confidence: 0.52)
Other confirmed entities: [Alice (PERSON)]

Is this span: (a) a person's name, (b) a country/location, (c) not PII?
```

The confirmed entities list is key — knowing "Alice" is already confirmed as a person in the same sentence provides strong signal that "Jordan" is likely also a person here.
