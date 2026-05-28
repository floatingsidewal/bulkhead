# Demo: Redacting a Support Ticket Before Sending to an LLM

## Goal

Sanitize user-provided content with `/v1/redact` so sensitive data is removed before the payload reaches an AI assistant.

## Scenario

A support platform forwards tickets to an LLM for summarization. Tickets may contain PII and secrets.

## 1) Start the server

```bash
npm run build
node packages/server/dist/main.js
```

## 2) Send a ticket for redaction

```bash
curl -X POST http://localhost:3000/v1/redact \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Customer Jane Doe (SSN 219-09-9999) reported billing issue. Contact: jane.doe@example.com. AWS key found: AKIAIOSFODNN7EXAMPLE"
  }'
```

## 3) Expected result

Bulkhead returns:

- `passed: false` (detections were found)
- `results` with guard-level detections (PII + secrets)
- `redactedText` with sensitive spans replaced

Example `redactedText`:

```text
Customer Jane Doe (SSN [REDACTED-US_SSN]) reported billing issue. Contact: [REDACTED-EMAIL_ADDRESS]. AWS key found: [REDACTED-AWS_ACCESS_KEY]
```

## 4) Forward only the sanitized text

Use `redactedText` as the LLM input, and keep `results` for audit/compliance logs.

## Why this works end-to-end

Bulkhead performs detection and redaction in one API call, so your application can enforce "sanitize before send" as a single pre-flight step.
