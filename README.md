# Bulkhead

**Content protection guardrails for AI-powered development tools.**

Bulkhead is a VS Code extension that detects and redacts sensitive content — PII, secrets, prompt injection, and system prompt leakage — before it leaks through LLM-powered features like code completion, chat, and inline suggestions.

## The Problem

Every time you use an AI coding assistant, your editor content gets sent to an LLM. That content can include:

- **Personal data** — SSNs, credit cards, emails, phone numbers, medical IDs
- **Secrets** — API keys, tokens, database credentials, private keys
- **Prompt injection** — malicious instructions hidden in code comments or data
- **System prompt leakage** — attempts to extract your AI tool's configuration

Bulkhead sits between your editor and the AI, catching sensitive content before it leaves.

## How It Works

Bulkhead uses a **cascading classifier** — three detection layers that trade off speed against depth:

| Layer | Speed | What it catches | When it runs |
|-------|-------|----------------|--------------|
| **Regex** | Sub-ms | Structured PII (SSN, credit cards, IBAN), secrets (AWS keys, tokens), injection patterns | Every keystroke (debounced) |
| **BERT** | 20-50ms | Names, locations, organizations — contextual entities regex can't catch | On-demand "Deep Scan" |
| **LLM** | 500ms-2s | Ambiguous cases ("Is 'Jordan' a person or country?") | Only for the ~5-10% of detections the BERT layer can't resolve |

Each detection carries **provenance** — which layer flagged it, at what confidence, and whether it's confirmed or needs review.

## What It Detects

### PII (45+ entity types across 20+ countries)
Ported from [Microsoft Presidio](https://github.com/microsoft/presidio) with checksum validation (Luhn, IBAN mod-97, Verhoeff) and context-aware scoring.

- **Generic:** Credit cards, email, IBAN, IP addresses, MAC addresses, phone numbers, URLs, crypto wallets, dates
- **US:** SSN, driver's license, passport, bank accounts, ITIN, Medicare (MBI), NPI, ABA routing, DEA license
- **UK:** NHS number, NINO, passport, postcode, vehicle registration
- **EU:** Spain NIF/NIE, Italy fiscal code/VAT/driver/passport/ID, Poland PESEL, Finland PIC, Sweden personnummer, Germany tax ID/passport
- **APAC:** Singapore NRIC/UEN, Australia ABN/ACN/TFN/Medicare, India PAN/Aadhaar/vehicle/voter/passport, Korea RRN/passport, Thailand TNIN
- **Africa:** Nigeria NIN

### Secrets (17 patterns)
AWS, GitHub, GitLab, Azure, GCP, JWT, private keys, npm, Slack, Stripe, SendGrid, Twilio, OpenAI, Anthropic, database connection strings, generic high-entropy strings.

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

### Run in VS Code

1. Open the `bulkhead/` folder in VS Code
2. Press `F5` to launch the Extension Development Host
3. Open any file — Bulkhead auto-scans on edit (regex layer, debounced)
4. Use the command palette:
   - `Bulkhead: Scan File` — regex scan
   - `Bulkhead: Deep Scan` — regex + BERT + LLM cascade

### Use as a library

```typescript
import { GuardrailsEngine } from "bulkhead/engine/engine";
import { PiiGuard } from "bulkhead/guards/pii.guard";
import { SecretGuard } from "bulkhead/guards/secret.guard";

const engine = new GuardrailsEngine();
engine.addGuard(new PiiGuard());
engine.addGuard(new SecretGuard());

const results = await engine.analyze("Email: john@example.com, Key: AKIAIOSFODNN7EXAMPLE");
// results[0].detections → [{ entityType: "EMAIL_ADDRESS", source: "regex", disposition: "confirmed", ... }]
// results[1].detections → [{ entityType: "AWS_ACCESS_KEY", source: "regex", disposition: "confirmed", ... }]
```

## Configuration

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

## Testing

```bash
npm test              # Run all 107 tests
npm run test:watch    # Watch mode
npm run lint          # Type-check
```

The test suite includes an [adversarial test suite](test/adversarial/) covering evasion techniques, false positive resistance, mixed-threat documents, and a "kitchen sink" document that triggers all threat types simultaneously.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full cascading classifier design.

## Attribution

Bulkhead draws on two open-source projects. See [ATTRIBUTION.md](ATTRIBUTION.md) for details.

- **[Microsoft Presidio](https://github.com/microsoft/presidio)** (MIT) — PII detection patterns, checksum algorithms, entity taxonomy
- **[HAI-Guardrails](https://github.com/presidio-oss/hai-guardrails)** (MIT) — Guard architecture, detection tactics, security patterns

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
