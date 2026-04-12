# Testing

## Running Tests

```bash
npm test              # Run all tests (185+ tests across 13 files)
npm run test:watch    # Watch mode — re-runs on file change
npm run lint          # Type-check without emitting
```

## Test Structure

```
packages/core/test/
├── guards/
│   ├── pii.guard.test.ts         PII detection (10 tests)
│   ├── secret.guard.test.ts      Secret detection (7 tests)
│   ├── injection.guard.test.ts   Injection + leakage (7 tests)
│   ├── engine.test.ts            Engine orchestration (4 tests)
│   └── testdata.guard.test.ts    Test data detection (13 tests)
├── cascade/
│   ├── cascade.test.ts           Cascade classifier + LLM layer (9 tests)
│   └── bert-integration.test.ts  BERT model integration (5 tests)
├── policy/
│   └── policy.test.ts            Policy system + risk assessment (13 tests)
├── adversarial/
│   └── adversarial.test.ts       Edge cases & evasion (70 tests)
└── perf/
    └── perf.test.ts              Performance benchmarks (18 tests)

packages/server/test/
├── http.test.ts                  HTTP REST endpoints (18 tests)
├── mcp.test.ts                   MCP tools (9 tests)
└── benchmark.test.ts             Server throughput (2 tests)
```

## Test Categories

### Unit Tests (`test/guards/`)

Basic guard behavior — does each guard detect what it should and ignore what it shouldn't?

- **PII Guard:** Credit card (Luhn validation), email, SSN (invalid pattern rejection), IPv4, IBAN (mod-97), context score boosting, redaction, entity filtering
- **Secret Guard:** AWS keys, GitHub PATs, private key headers, JWTs, database URLs, clean text passthrough, redaction mode
- **Injection Guard:** Pattern matching ("ignore previous instructions"), heuristic matching (DAN mode, jailbreak), clean text passthrough
- **Engine:** Multi-guard orchestration, pass/fail aggregation, config-based guard disabling

### Cascade Tests (`test/cascade/`)

The cascading classifier with mock layers:

- Regex provenance (`source: "regex"`, `disposition: "confirmed"`)
- Cascade result structure (guard name, reason, source layers)
- Deep scan fallback when BERT is disabled
- LLM disambiguation with mock provider (confirm person, dismiss country)
- Graceful handling when no LLM provider is configured

### Adversarial Tests (`test/adversarial/`)

The most thorough suite — 70 tests across 10 categories:

#### PII Evasion (27 tests)
- **SSN obfuscation:** dashes, dots, spaces, no delimiters, plus rejection of all-same-digit, 666 prefix, 9xx (ITIN range), zero groups, zero serial
- **Credit card obfuscation:** spaces, dashes, no spaces, Luhn rejection, Amex (15-digit), Mastercard
- **Email edge cases:** plus-addressing, subdomains, unusual local parts
- **Phone formats:** parentheses, dots, international +1, leading 1
- **IBAN variations:** with/without spaces, German IBAN, invalid checksum rejection

#### False Positive Resistance (6 tests)
Things that look like PII but aren't:
- Version numbers (`v18.19.0`) should not match as phone numbers
- UUIDs should not match as credit cards
- Hex color codes should not match as MAC addresses
- Code constants (`PORT = 8080`) should not match as SSN
- ISO dates should not produce high-confidence non-date detections

#### Secret Edge Cases (9 tests)
Secrets in realistic contexts:
- AWS key inside JSON
- GitHub token in `.env` format
- Private key in multi-line document
- Slack token in code comment
- JWT in Authorization header
- Database URL with embedded credentials
- Stripe, Anthropic, SendGrid keys

#### Injection & Leakage (10 tests)
- Basic injection, varied phrasing, DAN mode, role-play, "from now on"
- Legitimate instructions should NOT trigger
- Direct/indirect prompt extraction, repeat-everything technique

#### Mixed-Threat Documents (5 tests)
Real-world scenarios where multiple threat types coexist:
- Multi-PII paragraph (email + SSN + credit card + phone + IP)
- PII + secrets in same document (database URL + AWS key + email + SSN)
- Injection hidden in legitimate meeting notes
- Full `.env` file with 5+ different secret types
- International PII from UK + Spain + Germany + India + Korea

#### Provenance & Redaction (7 tests)
- All regex detections carry `source: "regex"`
- All regex detections carry `disposition: "confirmed"`
- Context windows are populated and bounded
- Start/end offsets map back to correct text spans
- Multi-PII redaction doesn't corrupt surrounding text
- JSON structure survives secret redaction
- Overlapping detections are deduplicated correctly

#### Performance (5 tests)
- Empty input
- 10,000-line input completes in <5 seconds
- Whitespace-only input
- Unicode/emoji input
- Random binary gibberish

#### Kitchen Sink (1 test)
A single document containing all threat types — emails, SSNs, credit cards, IPs, AWS keys, database URLs, Stripe keys, GitHub tokens, private keys, UK NHS numbers. Verifies all are detected with correct provenance.

## Writing New Tests

When adding a new pattern or guard:

1. Add unit tests in `test/guards/` for the basic happy path
2. Add adversarial tests in `test/adversarial/` for evasion and false positives
3. Update the Kitchen Sink test if a new entity type should be caught
4. Run the full suite: `npm test`

### Test Helpers

The adversarial test file exports helpers you can reuse:

```typescript
// Check if a specific entity type was detected
await detectsEntity(engine, "some text", "US_SSN") // → boolean

// Get all detections from all guards
await allDetections(engine, "some text") // → Detection[]
```
