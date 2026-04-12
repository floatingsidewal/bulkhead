# Bulkhead Core

Cascading content protection engine -- detects and redacts PII, secrets, prompt injection, and system prompt leakage in text before it reaches LLMs.

Part of the [Bulkhead](https://github.com/floatingsidewal/bulkhead) project.

## Install

This package is available under two scopes:

```bash
npm install @bulkhead-ai/core
# or
npm install @floatingsidewal/bulkhead-core
```

Both packages are identical. Use whichever scope fits your project.

## Quick Start

```typescript
import { createEngine } from "@bulkhead-ai/core";
// or: import { createEngine } from "@floatingsidewal/bulkhead-core";

const engine = createEngine();

// Fast regex-only scan (sub-millisecond)
const result = await engine.analyze("My SSN is 123-45-6789 and key is AKIAIOSFODNN7EXAMPLE");

console.log(result.passed);      // false
console.log(result.detections);   // [{ entityType: "US_SSN", ... }, { entityType: "AWS_ACCESS_KEY", ... }]

// Scan and redact
const redacted = await engine.scan("Call me at 555-867-5309");
console.log(redacted.redactedText); // "Call me at [REDACTED-US_PHONE]"
```

## What It Detects

| Category | Coverage |
|----------|----------|
| **PII** | 45+ entity types across 20+ countries (SSN, credit cards, IBAN, phone, email, medical IDs, national IDs) |
| **Secrets** | 154 patterns across 13 categories (AWS, Azure, GCP, GitHub, Slack, Stripe, database credentials, private keys) |
| **Prompt Injection** | 16+ patterns (role-play attacks, DAN mode, instruction override) |
| **System Prompt Leakage** | 7+ patterns (prompt extraction, "repeat everything above") |

All structured patterns include checksum validation where applicable (Luhn, IBAN mod-97, Verhoeff).

## Configuration

```typescript
import { createEngine, type BulkheadConfig } from "@bulkhead-ai/core";

const engine = createEngine({
  enabled: true,
  debounceMs: 500,
  guards: {
    pii: { enabled: true },
    secret: { enabled: true },
    injection: { enabled: true },
    contentSafety: { enabled: false },
  },
  cascade: {
    modelEnabled: false,       // Enable BERT layer (see below)
    escalationThreshold: 0.75,
    contextSentences: 3,
    modelId: "Xenova/bert-base-NER",
  },
});
```

## Custom Guard Composition

For fine-grained control, compose guards directly:

```typescript
import { GuardrailsEngine, PiiGuard, SecretGuard } from "@bulkhead-ai/core";

const engine = new GuardrailsEngine();
engine.addGuard(new PiiGuard());
engine.addGuard(new SecretGuard());
// Skip injection/leakage guards if not needed
```

## BERT Layer (Optional)

The regex layer catches structured patterns. For contextual entities like names, locations, and organizations, enable the BERT layer:

```bash
npm install @huggingface/transformers
```

```typescript
const engine = createEngine({
  // ...
  cascade: {
    modelEnabled: true,  // Enables BERT NER model
    // ...
  },
});

// Use deepScan for full cascade (regex + BERT + optional LLM)
const result = await engine.deepScan("Send the report to John Smith at Acme Corp");

// Or modelScan for regex + BERT only (no LLM)
const result = await engine.modelScan(text);
```

The BERT model (~29 MB) downloads on first inference and runs in a worker thread. No GPU required.

## API

### `createEngine(config?)`

Creates a configured engine from a `BulkheadConfig`. Returns a `GuardrailsEngine`.

### `engine.analyze(text)`

Layer 1 only (regex). Sub-millisecond. Returns `{ passed, detections, stats }`.

### `engine.scan(text)`

Layer 1 scan with redaction. Returns `{ passed, detections, redactedText, stats }`.

### `engine.modelScan(text)`

Regex + BERT (Layers 1-2). Requires `cascade.modelEnabled: true`.

### `engine.deepScan(text)`

Full cascade (Layers 1-3). Requires cascade configuration.

### `engine.dispose()`

Cleanup (terminates BERT worker thread if running).

## Documentation

See the [full documentation](https://github.com/floatingsidewal/bulkhead/tree/develop/docs) for architecture details, deployment guides, and API reference.

## License

MIT
