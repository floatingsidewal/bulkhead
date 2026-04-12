# Bulkhead Server

HTTP REST and MCP server for the [Bulkhead](https://github.com/floatingsidewal/bulkhead) content protection engine.

## Install

This package is available under two scopes:

```bash
npm install @bulkhead-ai/server
# or
npm install @floatingsidewal/bulkhead-server
```

Both packages are identical. Use whichever scope fits your project.

## MCP Server

Exposes three tools via the Model Context Protocol (stdio transport):

| Tool | Description |
|------|-------------|
| `bulkhead_scan` | Scan text for PII, secrets, injection. Modes: `fast` (regex), `model` (regex+BERT), `deep` (full cascade) |
| `bulkhead_redact` | Scan and return redacted text with `[REDACTED-TYPE]` placeholders |
| `bulkhead_configure` | Enable/disable guards at runtime |

### Claude Code

Add to your project's `.mcp.json`:

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

Or if installed via npm:

```bash
npx bulkhead-mcp
```

### GitHub Copilot

Add to `.github/copilot/mcp.json` with the same format.

## HTTP REST Server

```bash
bulkhead-server
# or
npx bulkhead-server
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/scan` | Regex-only scan (sub-ms) |
| POST | `/v1/scan/model` | Regex + BERT |
| POST | `/v1/scan/deep` | Full cascade (regex + BERT + LLM) |
| POST | `/v1/redact` | Scan and redact |
| GET | `/healthz` | Health check |
| GET | `/readyz` | Readiness (BERT model loaded?) |
| GET | `/info` | Guard configuration summary |

### Request Format

```bash
curl -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789"}'
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BULKHEAD_PORT` | `3000` | Server port |
| `BULKHEAD_HOST` | `0.0.0.0` | Bind address |
| `BULKHEAD_API_KEY` | -- | Enable API key auth (via `X-API-Key` header) |
| `BULKHEAD_LOG_LEVEL` | `info` | Log level |
| `BULKHEAD_CASCADE_MODEL_ENABLED` | `false` | Enable BERT layer |
| `BULKHEAD_LLM_PROVIDER` | -- | LLM provider: `openai`, `anthropic`, or `custom` |
| `BULKHEAD_LLM_API_KEY` | -- | LLM provider API key |
| `BULKHEAD_LLM_ENDPOINT` | -- | Custom LLM endpoint URL |

## Docker

```bash
# HTTP mode
docker run -p 3000:3000 ghcr.io/floatingsidewal/bulkhead:latest

# MCP mode (stdio)
docker run --rm -i ghcr.io/floatingsidewal/bulkhead:latest packages/server/dist/mcp/index.js
```

See the [deployment guide](https://github.com/floatingsidewal/bulkhead/tree/develop/docs/deployment.md) for Docker configuration details.

## License

MIT
