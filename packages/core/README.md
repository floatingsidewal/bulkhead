# Bulkhead Core

Cascading content protection engine -- detects and redacts PII, secrets, prompt injection, and system prompt leakage in text before it reaches LLMs.

Part of the [Bulkhead](https://github.com/floatingsidewal/bulkhead) project.

## Install

```bash
npm install @bulkhead-ai/core
```

Also available as `@floatingsidewal/bulkhead-core` via [GitHub Packages](https://github.com/floatingsidewal/bulkhead/packages).

## Quick Start

```typescript
import { createEngine } from "@bulkhead-ai/core";

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

## Policy Scanning

```typescript
import { createEngine, getPolicy } from "@bulkhead-ai/core";

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
    modelEnabled: false,
    escalationThreshold: 0.75,
    contextSentences: 3,
    modelId: "Xenova/bert-base-NER",
  },
  policy: "strict",
});

const policy = getPolicy("strict");
const { risk } = await engine.policyScan(inputText, policy);
console.log(risk.level);        // "critical" | "high" | "medium" | "low" | "none"
console.log(risk.issues);       // classified issues by category and severity
console.log(risk.testDataFlags); // synthetic/eval data detected
```

## BERT Layer (Optional)

For contextual entities like names, locations, and organizations:

```bash
npm install @huggingface/transformers
```

```typescript
const engine = createEngine({
  // ...
  cascade: { modelEnabled: true, /* ... */ },
});

const result = await engine.deepScan("Send the report to John Smith at Acme Corp");
```

The BERT model (~29 MB) downloads on first inference and runs in a worker thread. No GPU required.

## Documentation

See the [How-To Guide](https://github.com/floatingsidewal/bulkhead/blob/develop/docs/how-to.md) for comprehensive examples and the [full documentation](https://github.com/floatingsidewal/bulkhead/tree/develop/docs) for architecture, deployment, and API reference.

## License

MIT
