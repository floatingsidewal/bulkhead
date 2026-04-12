# Architecture

## Overview

The cascading classifier is Bulkhead's core architectural contribution. The detection
patterns are ported from established open-source projects (Microsoft Presidio for PII,
HAI-Guardrails for secrets and injection -- see [ATTRIBUTION.md](../ATTRIBUTION.md)).
What Bulkhead adds is the three-layer cascade that routes detections through
progressively more expensive classifiers, the BERT worker thread integration, the LLM
disambiguation layer, the multi-platform server architecture, and the deduplication logic
that merges results across layers.

## Monorepo Structure

Bulkhead is organized as an npm workspace monorepo with three packages:

```
bulkhead/
  packages/
    core/       @floatingsidewal/bulkhead-core      Detection engine, guards, cascade, patterns
    vscode/     bulkhead            VS Code extension (depends on core)
    server/     @floatingsidewal/bulkhead-server    HTTP REST + MCP server (depends on core)
  Dockerfile                        Multi-stage build for containerized deployment
  docker-compose.yml                HTTP and MCP service definitions
  .mcp.json                         Claude Code MCP configuration
  .github/copilot/mcp.json          GitHub Copilot MCP configuration
```

**Dependency graph:**

```
@floatingsidewal/bulkhead-core        (no internal deps — standalone library)
    ^         ^
    |         |
bulkhead   @floatingsidewal/bulkhead-server
(vscode)   (fastify + MCP SDK)
```

`@floatingsidewal/bulkhead-core` is the shared detection engine. Both the VS Code extension and the
server package depend on it. Core has no dependency on VS Code APIs or Fastify -- it is a
pure TypeScript library that can run in any Node.js environment.

## Cascading Classifier

The cascade uses three detection layers that progressively trade speed for depth. Each layer acts as a filter that only escalates what it can't resolve with confidence.

```
                     Input Text
                         |
          +--------------v---------------+
          |   Layer 1: Regex (sub-ms)    |  Always on. Catches structured PII,
          |   45+ patterns, checksums    |  secrets, injection patterns.
          |   confidence: 1.0            |  ~60-70% of detections stop here.
          |   disposition: "confirmed"   |
          +--------------+---------------+
                         | full text
          +--------------v---------------+
          |  Layer 2: BERT (20-50ms)     |  On-demand. Catches names, locations,
          |  28.5M params, INT8 ~29MB    |  organizations, contextual entities.
          |  Worker thread, lazy-load    |  Returns real confidence scores.
          |  >=0.75 -> "confirmed"       |
          |  <0.75  -> "escalate"        |
          +--------------+---------------+
                         | only escalated spans + context
          +--------------v---------------+
          |  Layer 3: LLM (500ms-2s)     |  Selective. Only sees ~5-10% of
          |  +/-3 sentences context      |  detections -- the genuinely ambiguous.
          |  Confirmed entities as       |  "Is 'Jordan' a person or country?"
          |  disambiguation signal       |
          |  -> "confirmed"/"dismissed"  |
          +------------------------------+
```

## Entry Points Into the Cascade

The cascade is reachable through five different entry points, all of which converge on the same `@floatingsidewal/bulkhead-core` engine:

```
VS Code Extension              HTTP REST Server           MCP Server
(packages/vscode)              (packages/server)          (packages/server/mcp)
     |                              |                          |
     |  Command Palette:            |  POST /v1/scan           |  bulkhead_scan
     |  "Scan File"                 |  POST /v1/scan/deep      |    mode: fast
     |  "Deep Scan"                 |  POST /v1/scan/model     |    mode: model
     |                              |  POST /v1/redact          |    mode: deep
     |  Auto-scan on edit           |                          |  bulkhead_redact
     |  (debounced)                 |                          |  bulkhead_configure
     |                              |                          |
     +----------+-------------------+----------+---------------+
                |                              |
                v                              v
        engine.analyze()               engine.deepScan()
        (Layer 1 only)                 engine.modelScan()
                |                      (Layer 1+2 or 1+2+3)
                |                              |
                +--------- @floatingsidewal/bulkhead-core -----+
                           GuardrailsEngine
                                |
                         CascadeClassifier
                          |      |      |
                        Regex  BERT    LLM
```

**Scan mode mapping across entry points:**

| Scan Depth | VS Code | HTTP Endpoint | MCP Tool |
|------------|---------|---------------|----------|
| Regex only | `Scan File`, auto-scan | `POST /v1/scan` | `bulkhead_scan` mode: `fast` |
| Regex + BERT | -- | `POST /v1/scan/model` | `bulkhead_scan` mode: `model` |
| Full cascade | `Deep Scan` | `POST /v1/scan/deep` | `bulkhead_scan` mode: `deep` |
| Scan + redact | -- | `POST /v1/redact` | `bulkhead_redact` |

## The Escalation Contract

Every detection carries provenance:

```typescript
interface Detection {
  entityType: string;        // "PERSON", "US_SSN", "AWS_ACCESS_KEY"
  text: string;              // the detected span
  score: number;             // 0-1 confidence
  source: "regex" | "bert" | "llm";
  context: string;           // surrounding text window (+/-150 chars)
  disposition: "confirmed" | "escalate" | "dismissed";
}
```

- **Regex** results always arrive with `confidence: 1.0`, `disposition: "confirmed"` -- they're deterministic.
- **BERT** results carry a real confidence score. Above the threshold (default 0.75) -> `confirmed`. Below -> `escalate`.
- **LLM** only sees escalated items plus their context. Returns `confirmed` or `dismissed`.

## Why This Works

**Cost proportionality.** Regex catches 60-70% of PII by volume (structured data is the most common leak). BERT resolves most of the remainder. The LLM handles 5-10% -- the genuinely ambiguous cases. Expensive inference runs on a tiny fraction of total work.

**Latency budget.** Regex is invisible (sub-ms on every keystroke, debounced). BERT runs on explicit "Deep Scan". LLM only fires on the handful of ambiguous spans, so the user sees "scanning... found 3 items needing review" rather than waiting for the whole document to process through an LLM.

**Auditability.** Each detection carries its provenance. When someone asks "why was this blocked?" you can say "regex matched SSN pattern with Luhn validation" or "BERT flagged a name at 0.92 confidence" rather than "the AI said so."

## Component Map

```
packages/core/src/
  index.ts                         Public API, createEngine(), BulkheadConfig
  types/index.ts                   Core type definitions (Detection, Guard, etc.)
  engine/engine.ts                 GuardrailsEngine -- orchestrates guards
  cascade/
    cascade.ts                     CascadeClassifier -- the three-layer orchestrator
    bert-layer.ts                  Main-thread BERT interface
    bert-worker.ts                 Worker thread for BERT inference
    llm-layer.ts                   LLM disambiguation (Layer 3)
  guards/
    base.guard.ts                  Base class with shared logic
    pii.guard.ts                   PII detection (45+ entity types)
    secret.guard.ts                Secret/credential detection (154 patterns)
    injection.guard.ts             Prompt injection detection
    leakage.guard.ts               System prompt leakage detection
  patterns/
    pii/                           PII regex patterns by region
      generic.ts                   Credit card, email, IBAN, IP, etc.
      us.ts                        SSN, driver's license, passport, etc.
      uk.ts                        NHS, NINO, postcode, etc.
      eu.ts                        Spain, Italy, Poland, Finland, Sweden, Germany
      apac.ts                      Singapore, Australia, India, Korea, Thailand, Nigeria
      index.ts                     Pattern registry
    secrets/                       Secret patterns by category (13 categories)
      cloud.ts                     AWS, Azure, GCP
      source-control.ts            GitHub, GitLab, Bitbucket
      cicd.ts                      Jenkins, CircleCI, Travis CI
      communication.ts             Slack, Twilio, SendGrid
      payment.ts                   Stripe, Square, PayPal
      database.ts                  Connection strings, Redis, MongoDB
      infrastructure.ts            Terraform, Vault, Consul
      saas.ts                      Jira, Datadog, New Relic
      ai-ml.ts                     OpenAI, Anthropic, HuggingFace
      auth.ts                      Auth0, Okta, Firebase, Clerk
      cdn-hosting.ts               Cloudflare, Netlify, Vercel
      social.ts                    Twitter, Facebook, LinkedIn
      generic.ts                   JWT, private keys, high-entropy strings
      index.ts                     Aggregated pattern registry
    injection.ts                   Injection/leakage patterns and keywords
  validators/
    checksums.ts                   Luhn, IBAN mod-97, ABA, NPI, DEA, Shannon entropy
    verhoeff.ts                    Verhoeff algorithm (Aadhaar, Nigerian NIN)

packages/vscode/src/
  extension.ts                     VS Code extension entry point, activation, lifecycle
  diagnostics.ts                   Detection -> VS Code diagnostic mapping
  code-actions.ts                  Quick fixes (redact, dismiss)
  commands.ts                      Command palette (scan, deep scan)
  config.ts                        Extension settings

packages/server/src/
  main.ts                          HTTP server entry point (Fastify)
  server.ts                        Fastify app factory (CORS, auth, error handling)
  config.ts                        Environment variable loading (FullConfig)
  llm-providers.ts                 LLM provider factory (OpenAI, Anthropic, custom)
  routes/
    scan.ts                        /v1/scan, /v1/scan/deep, /v1/scan/model, /v1/redact
    health.ts                      /healthz, /readyz, /v1/info
  mcp/
    index.ts                       MCP server entry point (stdio transport)
    mcp-server.ts                  MCP tool definitions (scan, redact, configure)
```

## Server Architecture

### HTTP REST Server

The HTTP server uses Fastify with the following design:

```
Request -> [CORS hook] -> [API key auth hook] -> Route handler -> Engine -> Response
                                                       |
                                           /v1/scan     -> engine.analyze()
                                           /v1/scan/deep -> engine.deepScan()
                                           /v1/scan/model -> engine.modelScan()
                                           /v1/redact    -> engine.scan()
                                           /healthz      -> { status: "ok" }
                                           /readyz       -> { status: "ready", guards }
                                           /v1/info      -> { name, version, guards }
```

Security features:
- Request bodies are never logged (they contain the sensitive data being scanned)
- API key authentication via `X-API-Key` header (optional, enabled by `BULKHEAD_API_KEY`)
- Health and readiness endpoints bypass authentication
- CORS disabled by default, configurable via `BULKHEAD_CORS_ORIGIN`
- Configurable body size limit (default 1MB)
- Runs as non-root user in Docker

### MCP Server

The MCP server uses the Model Context Protocol SDK with stdio transport:

```
AI Assistant (stdin/stdout) <-> StdioServerTransport <-> McpServer <-> Engine
                                                            |
                                              bulkhead_scan      -> engine.analyze/deepScan/modelScan
                                              bulkhead_redact    -> engine.scan
                                              bulkhead_configure -> engine.updateConfig
```

The MCP server exposes the same engine through three tools:
- `bulkhead_scan` -- scan with selectable mode (fast/model/deep)
- `bulkhead_redact` -- scan and return redacted text
- `bulkhead_configure` -- enable/disable guards at runtime

## Container Deployment

The Dockerfile uses a multi-stage build to minimize the runtime image:

```
Stage 1 (builder):
  node:20-slim
  npm ci (all deps including devDependencies)
  tsup build: core first, then server

Stage 2 (runtime):
  node:20-slim
  Non-root user (bulkhead:bulkhead)
  Only dist/ artifacts + production node_modules
  /app/models volume for BERT model cache
  HEALTHCHECK against /healthz
```

The same image supports both HTTP and MCP modes:
- `docker run bulkhead` -- HTTP server on port 3000 (default)
- `docker run -i bulkhead packages/server/dist/mcp/index.js` -- MCP server on stdio

## Training Pipeline (Independent)

The `training/` directory contains a separate Python pipeline for fine-tuning and exporting BERT models. It shares nothing with the runtime except the ONNX model artifact.

```
training/              -> Python (torch, transformers, optimum)
    | produces
models/*.onnx          -> ONNX model artifact (the contract)
    | consumed by
packages/core/src/cascade/    -> TypeScript (@huggingface/transformers)
```

See [training/README.md](../training/README.md) for details.

## VS Code Integration

```
Auto-scan (on edit, debounced 500ms)
  -> engine.analyze() -> Layer 1 only (regex)
  -> Diagnostics shown inline

"Bulkhead: Scan File" command
  -> engine.analyze() -> Layer 1 only

"Bulkhead: Deep Scan" command
  -> engine.deepScan() -> Full cascade (Layer 1 + 2 + 3)
  -> Progress indicator while BERT/LLM run
  -> Diagnostics show source: [Bulkhead/regex], [Bulkhead/bert], [Bulkhead/llm]
  -> Escalated items shown as info-level "needs review"

Code Actions (Quick Fixes)
  -> "Redact EMAIL_ADDRESS" -> replaces with [REDACTED-EMAIL_ADDRESS]
  -> "Dismiss this warning"
```

## Context Window (Layer 3)

When BERT flags an ambiguous span, the LLM receives:

1. **+/-3 sentences** around the flagged span
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

The confirmed entities list is key -- knowing "Alice" is already confirmed as a person in the same sentence provides strong signal that "Jordan" is likely also a person here.
