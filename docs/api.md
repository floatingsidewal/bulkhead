# API Reference

## Core Engine API

`@bulkhead-ai/core` exposes a `GuardrailsEngine` class for use as a library. This is the same engine the HTTP and MCP servers wrap; consumers embedding bulkhead directly (eg. eval-corpus harvesters, custom CLI tools) call these methods.

```ts
import { createEngine, getPolicy } from "@bulkhead-ai/core";

const engine = createEngine({ policy: "moderate" });
const result = await engine.scan("Email: john@example.com");
console.log(result.redactedText); // "Email: [REDACTED-EMAIL_ADDRESS]"
```

### `sanitizeDocument(input, policy, options?)`

Sanitizes a JSON-compatible value with one document-wide treatment plan.
Unlike repeated `scan()` calls, it scans object keys and string values before
mutation, arbitrates cross-guard overlaps, shares replacement consistency and
the temporal anchor across every leaf, reconstructs the value natively, and
runs a logical residual-safety check.

```ts
import {
  sanitizeDocument,
  type SanitizePolicy,
} from "@bulkhead-ai/core";

const policy: SanitizePolicy = "eval";
const result = await sanitizeDocument(payload, policy, {
  localizedDateOrder: "reject-ambiguous",
  detectedUnparseableDateReplacement: "[REDACTED-DATE_TIME]",
});

if (!result.metadata.postTreatment.safe ||
    !result.metadata.postTreatment.structurallyValid) {
  throw new Error("Sanitization boundary rejected output");
}

send(JSON.stringify(result.value));
```

`localizedDateOrder` accepts `"mdy"`, `"dmy"`, or `"reject-ambiguous"`
(the default). ISO timestamps, `yyyy-mm-dd`, and unambiguous localized dates
can be rebased by temporal policy. Ambiguous, short-year, invalid, or otherwise
unparseable detected dates receive the configured fallback and never an
identity replacement.

`metadata.detectedRisk` describes the original detections and selected
treatments. `metadata.postTreatment` independently reports residual safety and
JSON structural validity. A detection count greater than zero does not mean the
treated value is unsafe.

Overlaps are resolved before offsets are applied. A fixed guard/confidence
precedence selects a full-span winner when safe; otherwise the union is replaced
with `[REDACTED]`. Sanitized key collisions receive deterministic
`[REDACTED-KEY-N]` names so entries are not silently lost.

`scan()`, `scanObject()`, and `policyScan()` remain available for compatibility
and lower-level text workflows. Consumers migrating object sanitization should
remove local date parsing, JSON escape repair, overlap mutation, and residual
substring shims while retaining their final fail-closed boundary check.

### `engine.scan(text)`

**Layer 1 only.** Runs all enabled regex-based guards. Sub-millisecond latency.

```ts
async scan(text: string): Promise<{
  passed: boolean;
  results: GuardResult[];
  redactedText?: string;
}>
```

| Field | Description |
|---|---|
| `passed` | `true` iff every guard passed (no detections above its threshold) |
| `results` | One `GuardResult` per registered guard, with detections + scores |
| `redactedText` | Present iff any guard ran in `mode: "redact"` and produced replacements |

Use `scan` when you want the cheapest possible detection pass, or you've already decided regex coverage is sufficient.

### `engine.modelScan(text)`

**Layer 1 + Layer 2.** Runs regex first, then escalates ambiguous tokens to the BERT model. ~20-50ms latency on warmed model. Returns the same shape as `scan`, but detections may include `source: "bert"`.

```ts
async modelScan(text: string): Promise<GuardResult[]>
```

Requires `engine.initCascade()` to have been called and the BERT model loaded. The first `modelScan` call after engine creation triggers model load (~1-2s cold-start); subsequent calls are warm.

Use `modelScan` for higher-recall PII detection (especially `PERSON_NAME`, `LOCATION`) without the latency cost of an LLM call.

### `engine.deepScan(text)`

**Layer 1 + 2 + 3.** Full cascade: regex, BERT, then LLM disambiguation for genuinely-ambiguous spans. ~500ms-2s latency depending on the LLM provider and how many spans escalate.

```ts
async deepScan(text: string): Promise<GuardResult[]>
```

Requires `engine.initCascade()` with `llmEnabled: true` and an `llmProvider` configured. See `docs/deployment.md` for provider setup.

Use `deepScan` for the highest-recall, lowest-false-positive output — typically for compliance audits, not per-keystroke scanning.

### `engine.policyScan(text, policy)`

Runs `scan` and produces a **risk assessment** alongside the standard results.

```ts
async policyScan(text: string, policy: PolicyDefinition): Promise<{
  passed: boolean;
  risk: RiskAssessment;
  results: GuardResult[];
  redactedText?: string;
}>
```

The `risk` field contains:

- `level`: `"critical" | "high" | "medium" | "low" | "none"`
- `score`: aggregate 0-1
- `guards`: per-guard breakdown
- `issues`: classified detections grouped by category
- `testDataFlags`: synthetic-data detections (eg. `00000000-eval-...` GUIDs)

Use `policyScan` when consumers need a summary judgment ("is this content safe to send to an LLM") rather than raw detection lists.

### Lifecycle

```ts
const engine = createEngine({ policy: "strict" });

// Optional: initialize the cascade for modelScan / deepScan
engine.initCascade({ bertEnabled: true });

// Ready check: returns true once BERT (if enabled) has loaded
await waitFor(() => engine.cascadeReady);

// ... scans ...

// Clean up the BERT worker thread
await engine.dispose();
```

---

## HTTP REST Endpoints


The HTTP server runs on Fastify at port 3000 (configurable via `BULKHEAD_PORT`). All `/v1/*` endpoints accept and return JSON.

### Authentication

Authentication is **disabled by default**. To enable it, set the `BULKHEAD_API_KEY` environment variable. When set, all `/v1/*` routes require the `X-API-Key` header. Health and readiness endpoints (`/healthz`, `/readyz`) bypass authentication.

```bash
# Start with authentication
BULKHEAD_API_KEY=my-secret-key node packages/server/dist/main.js

# Authenticated request
curl -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-secret-key" \
  -d '{"text": "test"}'
```

Unauthenticated requests to protected endpoints return:

```json
{ "error": "Unauthorized" }
```

with HTTP status `401`.

---

### POST /v1/scan

Run Layer 1 (regex) scan. Sub-millisecond latency.

**Request:**

```json
{
  "text": "My SSN is 123-45-6789 and key is AKIAIOSFODNN7EXAMPLE",
  "config": {
    "guards": {
      "pii": { "enabled": true },
      "secret": { "enabled": false }
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | yes | The text to scan |
| `config` | object | no | Runtime guard configuration overrides |

**Response:**

```json
{
  "passed": false,
  "results": [
    {
      "guardName": "PiiGuard",
      "passed": false,
      "score": 0,
      "detections": [
        {
          "entityType": "US_SSN",
          "text": "123-45-6789",
          "score": 1,
          "confidence": 1,
          "source": "regex",
          "context": "My SSN is 123-45-6789 and key is...",
          "disposition": "confirmed"
        }
      ]
    },
    {
      "guardName": "SecretGuard",
      "passed": false,
      "score": 0,
      "detections": [
        {
          "entityType": "AWS_ACCESS_KEY",
          "text": "AKIAIOSFODNN7EXAMPLE",
          "score": 1,
          "confidence": 1,
          "source": "regex",
          "context": "...and key is AKIAIOSFODNN7EXAMPLE",
          "disposition": "confirmed"
        }
      ]
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `passed` | boolean | `true` if no detections across all guards |
| `results` | array | One entry per guard |
| `results[].guardName` | string | Guard name (PiiGuard, SecretGuard, InjectionGuard, LeakageGuard) |
| `results[].passed` | boolean | `true` if this guard found no issues |
| `results[].score` | number | Aggregate guard score (0 = detections found, 1 = clean) |
| `results[].detections` | array | Individual detections |
| `results[].detections[].entityType` | string | Detection type (e.g., US_SSN, AWS_ACCESS_KEY) |
| `results[].detections[].text` | string | The matched text span |
| `results[].detections[].score` | number | Confidence score 0-1 |
| `results[].detections[].source` | string | Which cascade layer: `regex`, `bert`, or `llm` |
| `results[].detections[].disposition` | string | `confirmed`, `escalate`, `dismissed`, or `informational` (test data) |

---

### POST /v1/scan/deep

Run the full cascade: Layer 1 (regex) + Layer 2 (BERT) + Layer 3 (LLM). Requires `BULKHEAD_CASCADE_MODEL_ENABLED=true`.

**Request:**

```json
{
  "text": "Alice and Jordan discussed the project yesterday."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | yes | The text to scan |

**Response:** Same schema as `/v1/scan`. Detections may include `source: "bert"` or `source: "llm"` in addition to `source: "regex"`.

---

### POST /v1/scan/model

Run Layer 1 (regex) + Layer 2 (BERT) without LLM escalation. Requires `BULKHEAD_CASCADE_MODEL_ENABLED=true`.

**Request:**

```json
{
  "text": "Jordan Smith lives in Portland."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | yes | The text to scan |

**Response:** Same schema as `/v1/scan`. BERT detections below the escalation threshold will have `disposition: "escalate"` but will not be sent to an LLM.

---

### POST /v1/redact

Scan text and return a redacted version with sensitive content replaced by `[REDACTED-TYPE]` placeholders.

**Request:**

```json
{
  "text": "Contact john@example.com or call 555-123-4567"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | yes | The text to redact |

**Response:**

```json
{
  "passed": false,
  "results": [ ... ],
  "redactedText": "Contact [REDACTED-EMAIL_ADDRESS] or call [REDACTED-PHONE_NUMBER]"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `passed` | boolean | `true` if no detections |
| `results` | array | Same as `/v1/scan` response |
| `redactedText` | string | Input text with detections replaced by `[REDACTED-TYPE]` |

---

### GET /healthz

Liveness probe. Returns 200 if the process is running. No authentication required.

**Response:**

```json
{ "status": "ok" }
```

---

### GET /readyz

Readiness probe. Returns 200 with the list of active guards. No authentication required.

**Response:**

```json
{
  "status": "ready",
  "guards": ["PiiGuard", "SecretGuard", "InjectionGuard", "LeakageGuard"]
}
```

---

### GET /v1/info

Server metadata. Returns version and active guard names.

**Response:**

```json
{
  "name": "bulkhead",
  "version": "0.5.3",
  "guards": ["PiiGuard", "SecretGuard", "InjectionGuard", "LeakageGuard"]
}
```

---

### Error Responses

**400 Bad Request** (validation error):

```json
{
  "error": "Bad Request",
  "message": "body must have required property 'text'"
}
```

**401 Unauthorized** (missing or invalid API key):

```json
{ "error": "Unauthorized" }
```

**500 Internal Server Error:**

```json
{
  "error": "Internal Server Error",
  "message": "An unexpected error occurred"
}
```

---

## MCP Tool Definitions

The MCP server exposes three tools via the Model Context Protocol over stdio transport.

### bulkhead_scan

Scan text for PII, secrets, prompt injection, and system prompt leakage.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `text` | string | yes | -- | The text to scan for sensitive content |
| `mode` | enum | no | `fast` | Scan mode: `fast` (regex only), `model` (regex + BERT), `deep` (full cascade with LLM) |

**Returns:** Two content blocks:
1. Human-readable summary with cascade layer breakdown
2. JSON with structured detection data

**Example response (text block):**

```
Found 2 detections:
  US_SSN (regex -> confirmed, 1.00)
  EMAIL_ADDRESS (regex -> confirmed, 1.00)

Cascade: regex only (2 detected) -- use mode: deep for full cascade
```

**Example response (JSON block):**

```json
{
  "passed": false,
  "detectionCount": 2,
  "results": [
    {
      "guardName": "PiiGuard",
      "passed": false,
      "score": 0,
      "detections": [
        {
          "entityType": "US_SSN",
          "text": "123-45-6789",
          "confidence": 1,
          "score": 1,
          "source": "regex",
          "disposition": "confirmed"
        }
      ]
    }
  ]
}
```

### bulkhead_redact

Scan text and return a redacted version with sensitive content replaced by `[REDACTED-TYPE]` placeholders.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `text` | string | yes | The text to redact |

**Returns:** Two content blocks:
1. Human-readable summary
2. JSON with `redactedText`, `passed`, `detectionCount`, and `detections`

**Example response (JSON block):**

```json
{
  "passed": false,
  "detectionCount": 1,
  "redactedText": "Contact [REDACTED-EMAIL_ADDRESS] for details",
  "detections": [
    {
      "entityType": "EMAIL_ADDRESS",
      "text": "john@example.com",
      "confidence": 1
    }
  ]
}
```

### bulkhead_configure

Enable or disable specific guards at runtime. Returns the current guard configuration.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `guards` | object | no | Guard configuration overrides. Keys are guard names (`pii`, `secret`, `injection`, `contentSafety`), values are `{ "enabled": boolean }` |

**Example input:**

```json
{
  "guards": {
    "pii": { "enabled": false },
    "secret": { "enabled": true }
  }
}
```

**Returns:**

```json
{
  "status": "ok",
  "activeGuards": ["SecretGuard", "InjectionGuard", "LeakageGuard"]
}
```

---

## Environment Variable Reference

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BULKHEAD_PORT` | `3000` | HTTP server port |
| `BULKHEAD_HOST` | `0.0.0.0` | HTTP server bind address |
| `BULKHEAD_LOG_LEVEL` | `info` | Log level: `info`, `warn`, `error`, `silent` |
| `BULKHEAD_API_KEY` | (empty) | API key for `X-API-Key` authentication. Empty = auth disabled |
| `BULKHEAD_CORS_ORIGIN` | (empty) | CORS `Access-Control-Allow-Origin`. Empty = CORS disabled |
| `BULKHEAD_MAX_BODY_SIZE` | `1048576` | Maximum request body size in bytes (1MB) |

### Guard Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BULKHEAD_ENABLED` | `true` | Master toggle for the engine |
| `BULKHEAD_GUARDS_PII_ENABLED` | `true` | Enable PII detection guard |
| `BULKHEAD_GUARDS_SECRET_ENABLED` | `true` | Enable secret/credential detection guard |
| `BULKHEAD_GUARDS_INJECTION_ENABLED` | `true` | Enable prompt injection + leakage detection guards |
| `BULKHEAD_GUARDS_CONTENT_SAFETY_ENABLED` | `false` | Enable LLM-based content safety guard |

### Cascade Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BULKHEAD_CASCADE_MODEL_ENABLED` | `false` | Enable BERT model for Layer 2 |
| `BULKHEAD_CASCADE_MODEL_ID` | `Xenova/bert-base-NER` | HuggingFace model ID for BERT |
| `BULKHEAD_CASCADE_ESCALATION_THRESHOLD` | `0.75` | BERT confidence threshold. Below this, detections escalate to LLM |
| `BULKHEAD_CASCADE_CONTEXT_SENTENCES` | `3` | Sentences of context sent to LLM for disambiguation |

### LLM Provider Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BULKHEAD_LLM_PROVIDER` | `none` | LLM provider for Layer 3: `none`, `openai`, `anthropic`, `custom` |
| `BULKHEAD_LLM_API_KEY` | (empty) | API key for the selected LLM provider |
| `BULKHEAD_LLM_ENDPOINT` | (empty) | Endpoint URL (required when `BULKHEAD_LLM_PROVIDER=custom`) |

### Docker / Container

| Variable | Default | Description |
|----------|---------|-------------|
| `TRANSFORMERS_CACHE` | `/app/models` | Directory for cached BERT model weights (set in Dockerfile) |
