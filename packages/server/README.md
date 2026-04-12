# Bulkhead Server

HTTP REST and MCP server for the [Bulkhead](https://github.com/floatingsidewal/bulkhead) content protection engine.

## Install

```bash
npm install @bulkhead-ai/server
```

Also available as `@floatingsidewal/bulkhead-server` via [GitHub Packages](https://github.com/floatingsidewal/bulkhead/packages) and as a Docker container at `ghcr.io/floatingsidewal/bulkhead`.

## MCP Server

Exposes three tools via the Model Context Protocol (stdio transport):

| Tool | Description |
|------|-------------|
| `bulkhead_scan` | Scan text for PII, secrets, injection. Modes: `fast` (regex), `model` (regex+BERT), `deep` (full cascade) |
| `bulkhead_redact` | Scan and return redacted text with `[REDACTED-TYPE]` placeholders |
| `bulkhead_configure` | Enable/disable guards at runtime |

### Claude Code / GitHub Copilot

Add to your project's `.mcp.json` (or `.github/copilot/mcp.json`):

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

## HTTP REST Server

```bash
npx bulkhead-server
# or
docker run -p 3000:3000 ghcr.io/floatingsidewal/bulkhead:latest
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

### Example

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

## Documentation

See the [How-To Guide](https://github.com/floatingsidewal/bulkhead/blob/develop/docs/how-to.md) for comprehensive examples and the [full documentation](https://github.com/floatingsidewal/bulkhead/tree/develop/docs) for architecture, deployment, and API reference.

## License

MIT
