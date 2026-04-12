# Deployment Guide

Bulkhead supports multiple deployment scenarios. Each uses the same `@bulkhead/core` detection engine with different transport layers.

## Consuming from Another Project

The fastest way to use Bulkhead from another project. Choose npm for library integration or Docker for MCP/HTTP server usage.

### npm (Library)

Add the GitHub Packages registry to your project's `.npmrc`:

```
@bulkhead:registry=https://npm.pkg.github.com
```

Install:

```bash
npm install @bulkhead/core
```

Use in your code:

```typescript
import { createEngine, getPolicy } from "@bulkhead/core";

// Simple scan (no policy)
const engine = createEngine();
const { passed, results } = await engine.scan("My SSN is 123-45-6789");

// Policy scan with risk assessment and test data detection
const policyEngine = createEngine({
  enabled: true,
  debounceMs: 500,
  guards: {
    pii: { enabled: true },
    secret: { enabled: true },
    injection: { enabled: true },
    contentSafety: { enabled: false },
  },
  cascade: {
    escalationThreshold: 0.75,
    contextSentences: 3,
    modelEnabled: false,
    modelId: "Xenova/bert-base-NER",
  },
  policy: "strict",
});

const policy = getPolicy("strict");
const { risk } = await policyEngine.policyScan(JSON.stringify(myData), policy);
console.log(risk.level);        // "critical" | "high" | "medium" | "low" | "none"
console.log(risk.issues);       // classified issues by category
console.log(risk.testDataFlags); // synthetic/eval data detected
```

For the HTTP/MCP server package:

```bash
npm install @bulkhead/server
```

Then run as an MCP server or HTTP server:

```bash
npx bulkhead-mcp    # MCP over stdio
npx bulkhead-server # HTTP on port 3000
```

### Docker Container (MCP Server)

No npm install required. Pull and run the pre-built container from GitHub Container Registry:

```bash
# MCP mode (stdio) — for AI assistant integration
docker run --rm -i ghcr.io/floatingsidewal/bulkhead:latest packages/server/dist/mcp/index.js

# HTTP mode — REST API on port 3000
docker run -p 3000:3000 ghcr.io/floatingsidewal/bulkhead:latest
```

Configure in your project's `.mcp.json` for Claude Code:

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/floatingsidewal/bulkhead:latest", "packages/server/dist/mcp/index.js"]
    }
  }
}
```

For GitHub Copilot, add to `.github/copilot/mcp.json` with the same format.

If the container registry is private, authenticate first:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

### Which Should I Use?

| Approach | Best for | Tradeoffs |
|----------|----------|-----------|
| **npm library** | In-process scanning, custom policies, risk assessment | Tightest integration, requires Node.js |
| **Docker MCP** | AI assistant integration (Claude Code, Copilot) | Zero install, isolated, no Node.js needed |
| **Docker HTTP** | Centralized scanning service, CI/CD pipelines | Language-agnostic, network overhead |
| **npm MCP/HTTP** | Lightweight server without Docker | Needs Node.js runtime installed |

---

## 1. VS Code Extension

**Use case:** Local development guardrails. Auto-scans files as you edit, flags PII and secrets before they reach your AI coding assistant.

### Setup

```bash
git clone https://github.com/your-org/bulkhead.git
cd bulkhead
npm install
npm run build
```

### Launch

1. Open the `bulkhead/` folder in VS Code
2. Press `F5` to launch the Extension Development Host
3. The extension activates on startup and auto-scans on edit

### Commands

| Command | Shortcut | Scan Depth |
|---------|----------|------------|
| `Bulkhead: Scan File` | -- | Regex only (sub-ms) |
| `Bulkhead: Deep Scan (Regex + BERT + LLM)` | -- | Full cascade |
| `Bulkhead: Check Content Safety` | -- | LLM-based content safety |

### Configuration

VS Code settings (Settings UI or `settings.json`):

```json
{
  "bulkhead.enabled": true,
  "bulkhead.debounceMs": 500,
  "bulkhead.guards.pii.enabled": true,
  "bulkhead.guards.secret.enabled": true,
  "bulkhead.guards.injection.enabled": true,
  "bulkhead.cascade.modelEnabled": false,
  "bulkhead.cascade.escalationThreshold": 0.75
}
```

Set `bulkhead.cascade.modelEnabled` to `true` to enable the BERT model. It downloads ~29MB on first use and runs in a worker thread.

### Expected Output

Detections appear as VS Code diagnostics inline in the editor:
- **Error:** Confirmed PII or secrets (regex or BERT with high confidence)
- **Warning:** Prompt injection or system prompt leakage
- **Info:** Escalated items that need review (BERT confidence below threshold)

Quick fixes offer "Redact [TYPE]" (replaces with `[REDACTED-EMAIL_ADDRESS]`) or "Dismiss this warning."

---

## 2. HTTP REST Server

**Use case:** CI/CD pipeline integration, API gateway sidecar, centralized scanning service. Run Bulkhead as a standalone HTTP server that other services call to scan content.

### Setup

```bash
cd bulkhead
npm install
npm run build
```

### Startup

```bash
# Development (with hot reload)
cd packages/server && npm run dev

# Production
node packages/server/dist/main.js

# With API key protection
BULKHEAD_API_KEY=my-secret-key node packages/server/dist/main.js

# With BERT + LLM enabled
BULKHEAD_CASCADE_MODEL_ENABLED=true \
BULKHEAD_LLM_PROVIDER=anthropic \
BULKHEAD_LLM_API_KEY=sk-ant-... \
node packages/server/dist/main.js
```

### Example Requests

**Regex scan (fast):**

```bash
curl -s -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789 and email is john@example.com"}'
```

**Expected output:**

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
          "source": "regex",
          "disposition": "confirmed"
        },
        {
          "entityType": "EMAIL_ADDRESS",
          "text": "john@example.com",
          "score": 1,
          "source": "regex",
          "disposition": "confirmed"
        }
      ]
    }
  ]
}
```

**Full cascade scan:**

```bash
curl -s -X POST http://localhost:3000/v1/scan/deep \
  -H "Content-Type: application/json" \
  -d '{"text": "Alice and Jordan discussed the project yesterday."}'
```

**Scan and redact:**

```bash
curl -s -X POST http://localhost:3000/v1/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact john@example.com or call 555-123-4567"}'
```

**Expected output:**

```json
{
  "passed": false,
  "results": [ ... ],
  "redactedText": "Contact [REDACTED-EMAIL_ADDRESS] or call [REDACTED-PHONE_NUMBER]"
}
```

**With API key authentication:**

```bash
curl -s -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-secret-key" \
  -d '{"text": "AKIAIOSFODNN7EXAMPLE"}'
```

**Health check:**

```bash
curl -s http://localhost:3000/healthz
# {"status":"ok"}

curl -s http://localhost:3000/readyz
# {"status":"ready","guards":["PiiGuard","SecretGuard","InjectionGuard","LeakageGuard"]}
```

---

## 3. MCP Server (AI Assistant Integration)

**Use case:** Give AI coding assistants (Claude Code, GitHub Copilot CLI) the ability to scan and redact content through the Model Context Protocol.

### Claude Code

Add `.mcp.json` to your project root. Use the published container (no local install needed):

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/floatingsidewal/bulkhead:latest", "packages/server/dist/mcp/index.js"]
    }
  }
}
```

Or if you have `@bulkhead/server` installed via npm:

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "npx",
      "args": ["bulkhead-mcp"]
    }
  }
}
```

### GitHub Copilot CLI

Add `.github/copilot/mcp.json` to your repository (same formats as above):

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/floatingsidewal/bulkhead:latest", "packages/server/dist/mcp/index.js"]
    }
  }
}
```

### Available Tools

Once connected, the AI assistant can use three tools:

**`bulkhead_scan`** -- Scan text for sensitive content.

Parameters:
- `text` (string, required): The text to scan
- `mode` (enum, optional): `fast` (regex only, default), `model` (regex + BERT), `deep` (full cascade)

**`bulkhead_redact`** -- Scan and return redacted text.

Parameters:
- `text` (string, required): The text to redact

**`bulkhead_configure`** -- Enable or disable guards at runtime.

Parameters:
- `guards` (object, optional): Guard overrides, e.g. `{ "pii": { "enabled": false } }`

### Expected Output

The MCP server returns two content blocks per tool call:
1. A human-readable summary with cascade layer breakdown
2. A JSON object with structured detection data

Example summary from `bulkhead_scan`:

```
Found 2 detections:
  US_SSN (regex -> confirmed, 1.00)
  EMAIL_ADDRESS (regex -> confirmed, 1.00)

Cascade: regex only (2 detected) -- use mode: deep for full cascade
```

---

## 4. Docker HTTP Server

**Use case:** Production deployment with container orchestration (Kubernetes, ECS, Docker Swarm). Hardened image with non-root user, read-only filesystem, and health checks.

### Build

```bash
docker build -t bulkhead .
```

### Startup

```bash
# Basic
docker run -p 3000:3000 bulkhead

# With API key
docker run -p 3000:3000 -e BULKHEAD_API_KEY=my-secret-key bulkhead

# With BERT model (persistent cache)
docker run -p 3000:3000 \
  -e BULKHEAD_CASCADE_MODEL_ENABLED=true \
  -v bulkhead-models:/app/models \
  bulkhead

# Using docker-compose
docker compose up bulkhead
```

### docker-compose.yml

The included `docker-compose.yml` runs the HTTP server with security defaults:

```yaml
services:
  bulkhead:
    build: .
    ports:
      - "3000:3000"
    environment:
      - BULKHEAD_PORT=3000
      - BULKHEAD_HOST=0.0.0.0
      - BULKHEAD_LOG_LEVEL=info
      - BULKHEAD_CASCADE_MODEL_ENABLED=false
    volumes:
      - bert-models:/app/models
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
```

### Example Requests

Same as the HTTP REST server examples above. The container exposes port 3000 by default.

```bash
curl -s -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "AWS key: AKIAIOSFODNN7EXAMPLE"}'
```

### Health Checks

The Docker image includes a built-in `HEALTHCHECK` that polls `/healthz` every 30 seconds. Compatible with Kubernetes liveness/readiness probes:

```yaml
# Kubernetes example
livenessProbe:
  httpGet:
    path: /healthz
    port: 3000
  initialDelaySeconds: 10
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /readyz
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Security Properties

- **Non-root user:** Runs as `bulkhead:bulkhead` (not root)
- **Read-only filesystem:** Only `/tmp` and `/app/models` are writable
- **No new privileges:** `no-new-privileges:true` prevents privilege escalation
- **No request body logging:** Sensitive content in request bodies is never written to logs
- **BERT model volume:** Model weights persist across container restarts via named volume

---

## 5. Docker MCP Server

**Use case:** Containerized AI assistant integration. Run the MCP server in Docker for isolation and reproducibility, connecting via stdio.

### Using the Published Image

```bash
# Pull from GitHub Container Registry
docker run --rm -i ghcr.io/floatingsidewal/bulkhead:latest packages/server/dist/mcp/index.js
```

### Building Locally

```bash
docker build -t bulkhead .
docker run --rm -i bulkhead packages/server/dist/mcp/index.js

# Or via docker-compose
docker compose run --rm -i bulkhead-mcp
```

### MCP Configuration (Docker)

For Claude Code, add to `.mcp.json`:

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/floatingsidewal/bulkhead:latest", "packages/server/dist/mcp/index.js"]
    }
  }
}
```

### docker-compose.yml

```yaml
services:
  bulkhead-mcp:
    build: .
    command: ["packages/server/dist/mcp/index.js"]
    stdin_open: true
    volumes:
      - bert-models:/app/models
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
```

### Expected Behavior

The MCP server communicates over stdin/stdout using the Model Context Protocol. The AI assistant sends JSON-RPC requests and receives JSON-RPC responses. The same three tools are available as in the non-Docker MCP deployment: `bulkhead_scan`, `bulkhead_redact`, `bulkhead_configure`.

The container has the same security properties as the HTTP Docker deployment: non-root user, read-only filesystem, no privilege escalation.
