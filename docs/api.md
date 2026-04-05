# API Reference

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
| `results[].detections[].disposition` | string | `confirmed`, `escalate`, or `dismissed` |

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
  "version": "0.1.0",
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
| `BULKHEAD_CASCADE_MODEL_ID` | `gravitee-io/bert-small-pii-detection` | HuggingFace model ID for BERT |
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
