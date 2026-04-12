# Bulkhead

**Cascading content protection for AI-powered development tools.**

Bulkhead detects and redacts sensitive content -- PII, secrets, prompt injection, and system prompt leakage -- before it leaks through LLM-powered features. It runs as a VS Code extension, an HTTP REST server, or an MCP server for AI coding assistants.

| | |
|---|---|
| **Deployment** | VS Code extension, HTTP REST server, MCP server, Docker |
| **Detection** | 154 secret patterns across 13 categories, 45+ PII entity types across 20+ countries, prompt injection, system prompt leakage, test data detection |
| **Architecture** | Three-layer cascading classifier (regex, BERT, LLM) |
| **Policy** | Named policies (strict, moderate), composable compliance overlays, risk assessment with classified issues |
| **Tests** | 185 tests including adversarial suite, policy system, and performance benchmarks |

## What Makes Bulkhead Different

The core innovation is the **cascading classifier** -- three detection layers that progressively trade speed for depth, so expensive inference only runs on the small fraction of content that actually needs it. Regex handles the bulk (sub-millisecond, every keystroke). A BERT model resolves contextual entities like names and locations. An LLM disambiguates the genuinely hard cases ("Is 'Jordan' a person or a country?"). Each detection carries full provenance -- which layer flagged it, at what confidence, and why.

The detection patterns themselves are ported from established open-source projects (see [Attribution](#attribution)). Bulkhead's contribution is the cascade architecture, the BERT worker thread integration, the LLM disambiguation layer, the multi-platform server architecture, and the deduplication logic that ties it all together.

## The Problem

Every time you use an AI coding assistant, your editor content gets sent to an LLM. That content can include:

- **Personal data** -- SSNs, credit cards, emails, phone numbers, medical IDs
- **Secrets** -- API keys, tokens, database credentials, private keys
- **Prompt injection** -- malicious instructions hidden in code comments or data
- **System prompt leakage** -- attempts to extract your AI tool's configuration

Bulkhead sits between your code and the AI, catching sensitive content before it leaves.

## Install


```
```

Then install:

```bash
# Core library (detection engine, guards, policies)
npm install @floatingsidewal/bulkhead-core

# HTTP REST + MCP server (optional)
npm install @floatingsidewal/bulkhead-server
```

### Quick Start

```typescript
import { createEngine, getPolicy } from "@floatingsidewal/bulkhead-core";

// Create a policy-aware engine
const engine = createEngine({
  enabled: true, debounceMs: 500,
  guards: { pii: { enabled: true }, secret: { enabled: true }, injection: { enabled: true }, contentSafety: { enabled: false } },
  cascade: { escalationThreshold: 0.75, contextSentences: 3, modelEnabled: false, modelId: "Xenova/bert-base-NER" },
  policy: "strict",
});

// Scan with risk assessment
const policy = getPolicy("strict");
const { risk } = await engine.policyScan("My SSN is 123-45-6789", policy);
console.log(risk.level);  // "high"
console.log(risk.issues);  // [{ category: "pii", entityType: "US_SSN", severity: "high", isTestData: true, ... }]
```

## Project Structure

```
bulkhead/
  packages/
    core/       @floatingsidewal/bulkhead-core    Detection engine, guards, cascade, policies
    vscode/     bulkhead          VS Code extension
    server/     @floatingsidewal/bulkhead-server  HTTP REST server + MCP server
  docs/                           Guides: architecture, API, policies, patterns
  Dockerfile                      Multi-stage build (HTTP + MCP modes)
  docker-compose.yml              HTTP and MCP service definitions
```

## How It Works

Bulkhead uses the **cascading classifier** -- three detection layers that trade off speed against depth:

| Layer | Speed | What it catches | When it runs |
|-------|-------|----------------|--------------|
| **Regex** | Sub-ms | Structured PII (SSN, credit cards, IBAN), secrets (AWS keys, tokens), injection patterns | Every keystroke (debounced) |
| **BERT** | 20-50ms | Names, locations, organizations -- contextual entities regex can't catch | On-demand "Deep Scan" or `/v1/scan/model` |
| **LLM** | 500ms-2s | Ambiguous cases ("Is 'Jordan' a person or country?") | Only for the ~5-10% of detections the BERT layer can't resolve |

Each detection carries **provenance** -- which layer flagged it, at what confidence, and whether it's confirmed or needs review.

## What It Detects

### PII (45+ entity types across 20+ countries)
Patterns ported from [Microsoft Presidio](https://github.com/microsoft/presidio) with checksum validation (Luhn, IBAN mod-97, Verhoeff) and context-aware scoring.

- **Generic:** Credit cards, email, IBAN, IP addresses, MAC addresses, phone numbers, URLs, crypto wallets, dates
- **US:** SSN, driver's license, passport, bank accounts, ITIN, Medicare (MBI), NPI, ABA routing, DEA license
- **UK:** NHS number, NINO, passport, postcode, vehicle registration
- **EU:** Spain NIF/NIE, Italy fiscal code/VAT/driver/passport/ID, Poland PESEL, Finland PIC, Sweden personnummer, Germany tax ID/passport
- **APAC:** Singapore NRIC/UEN, Australia ABN/ACN/TFN/Medicare, India PAN/Aadhaar/vehicle/voter/passport, Korea RRN/passport, Thailand TNIN
- **Africa:** Nigeria NIN

### Secrets (154 patterns across 13 categories)
Patterns sourced from HAI-Guardrails, GitLeaks, and public provider documentation.

- **Cloud:** AWS, Azure, GCP
- **Source control:** GitHub, GitLab, Bitbucket
- **CI/CD:** Jenkins, CircleCI, Travis CI, Drone
- **Communication:** Slack, Twilio, SendGrid, Mailgun
- **Payment:** Stripe, Square, PayPal
- **Database:** Connection strings, Redis, MongoDB
- **Infrastructure:** Terraform, Vault, Consul
- **SaaS:** Jira, Confluence, Datadog, New Relic
- **AI/ML:** OpenAI, Anthropic, HuggingFace, Cohere
- **Auth:** Auth0, Okta, Firebase, Clerk, Supabase
- **CDN/Hosting:** Cloudflare, Netlify, Vercel, Heroku
- **Social:** Twitter, Facebook, LinkedIn
- **Generic:** JWT, private keys, high-entropy strings

### Prompt Injection
16 regex patterns + heuristic similarity matching against known attack phrases. Catches: "ignore previous instructions", role-play attacks, DAN mode, jailbreak attempts.

### System Prompt Leakage
7 regex patterns + heuristic matching. Catches: "reveal your system prompt", "repeat everything above", extraction techniques.

## Quick Start

### Install from source

```bash
git clone https://github.com/your-org/bulkhead.git
cd bulkhead
npm install
npm run build
```

### VS Code Extension

1. Open the `bulkhead/` folder in VS Code
2. Press `F5` to launch the Extension Development Host
3. Open any file -- Bulkhead auto-scans on edit (regex layer, debounced)
4. Use the command palette:
   - `Bulkhead: Scan File` -- regex scan
   - `Bulkhead: Deep Scan` -- regex + BERT + LLM cascade

### HTTP REST Server

```bash
# Development
cd packages/server && npm run dev

# Production
npm run build && node packages/server/dist/main.js

# With API key authentication
BULKHEAD_API_KEY=my-secret-key node packages/server/dist/main.js
```

```bash
# Scan text
curl -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789"}'

# Scan and redact
curl -X POST http://localhost:3000/v1/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789"}'
```

### MCP Server (Claude Code)

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "npx",
      "args": ["tsx", "packages/server/src/mcp/index.ts"]
    }
  }
}
```

### MCP Server (GitHub Copilot CLI)

Add to `.github/copilot/mcp.json`:

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "npx",
      "args": ["tsx", "packages/server/src/mcp/index.ts"]
    }
  }
}
```

### Docker

```bash
# HTTP server on port 3000
docker compose up bulkhead

# MCP server on stdio
docker compose run --rm -i bulkhead-mcp
```

### Use as a library

```typescript
import { GuardrailsEngine, PiiGuard, SecretGuard } from "@floatingsidewal/bulkhead-core";

const engine = new GuardrailsEngine();
engine.addGuard(new PiiGuard());
engine.addGuard(new SecretGuard());

const results = await engine.analyze("Email: john@example.com, Key: AKIAIOSFODNN7EXAMPLE");
// results[0].detections -> [{ entityType: "EMAIL_ADDRESS", source: "regex", disposition: "confirmed", ... }]
// results[1].detections -> [{ entityType: "AWS_ACCESS_KEY", source: "regex", disposition: "confirmed", ... }]
```

## Configuration

### VS Code Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `bulkhead.enabled` | `true` | Master toggle |
| `bulkhead.debounceMs` | `500` | Delay before auto-scan on edit |
| `bulkhead.guards.pii.enabled` | `true` | PII detection |
| `bulkhead.guards.secret.enabled` | `true` | Secret detection |
| `bulkhead.guards.injection.enabled` | `true` | Prompt injection detection |
| `bulkhead.cascade.modelEnabled` | `false` | Enable BERT model (downloads ~29MB on first use) |
| `bulkhead.cascade.escalationThreshold` | `0.75` | BERT confidence below which detections escalate to LLM |
| `bulkhead.cascade.contextSentences` | `3` | Sentences of context sent to LLM for disambiguation |

### Environment Variables (Server)

| Variable | Default | Description |
|----------|---------|-------------|
| `BULKHEAD_PORT` | `3000` | HTTP server port |
| `BULKHEAD_HOST` | `0.0.0.0` | HTTP server bind address |
| `BULKHEAD_LOG_LEVEL` | `info` | Log level: `info`, `warn`, `error`, `silent` |
| `BULKHEAD_API_KEY` | (none) | API key for authentication. When set, all `/v1/*` routes require `X-API-Key` header |
| `BULKHEAD_CORS_ORIGIN` | (disabled) | CORS origin. Set to `*` or a specific origin to enable |
| `BULKHEAD_MAX_BODY_SIZE` | `1048576` | Maximum request body size in bytes (default 1MB) |
| `BULKHEAD_GUARDS_PII_ENABLED` | `true` | Enable PII guard |
| `BULKHEAD_GUARDS_SECRET_ENABLED` | `true` | Enable secret guard |
| `BULKHEAD_GUARDS_INJECTION_ENABLED` | `true` | Enable injection guard |
| `BULKHEAD_CASCADE_MODEL_ENABLED` | `false` | Enable BERT model for Layer 2 |
| `BULKHEAD_CASCADE_MODEL_ID` | `gravitee-io/bert-small-pii-detection` | HuggingFace model ID |
| `BULKHEAD_CASCADE_ESCALATION_THRESHOLD` | `0.75` | BERT confidence threshold for LLM escalation |
| `BULKHEAD_LLM_PROVIDER` | `none` | LLM provider: `openai`, `anthropic`, `custom` |
| `BULKHEAD_LLM_API_KEY` | (none) | API key for the LLM provider |
| `BULKHEAD_LLM_ENDPOINT` | (none) | Endpoint URL for custom LLM provider |

## Testing

```bash
npm test              # Run all 125 tests
npm run test:watch    # Watch mode (core package)
npm run lint          # Type-check all packages
```

The test suite includes an [adversarial test suite](test/adversarial/) covering evasion techniques, false positive resistance, mixed-threat documents, performance benchmarks with ASCII bar charts, and a "kitchen sink" document that triggers all threat types simultaneously.

## Documentation

- [Architecture](docs/architecture.md) -- Cascading classifier design, component map, entry points
- [Policy Guide](docs/policy.md) -- Policies, risk assessment, test data detection, compliance overlays
- [Deployment](docs/deployment.md) -- Five deployment scenarios with configuration and examples
- [API Reference](docs/api.md) -- HTTP endpoints, MCP tools, environment variables
- [Guards](docs/guards.md) -- Guard implementation details
- [Patterns](docs/patterns.md) -- Detection pattern reference
- [Testing](docs/testing.md) -- Test strategy and adversarial suite
- [How-To](docs/how-to.md) -- Usage guides and library integration

## Attribution

Bulkhead derives detection patterns and guard architecture from two open-source
projects. The cascading classifier, BERT integration, LLM disambiguation, VS Code
extension, server architecture, and deduplication logic are independently developed. See
[ATTRIBUTION.md](ATTRIBUTION.md) for full details and [NOTICES](NOTICES) for
original copyright notices.

- **[Microsoft Presidio](https://github.com/microsoft/presidio)** (MIT) -- PII detection patterns, checksum algorithms, entity taxonomy
- **[HAI-Guardrails](https://github.com/presidio-oss/hai-guardrails)** (MIT) -- Guard architecture, detection tactics, security patterns

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
