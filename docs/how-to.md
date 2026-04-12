# Bulkhead Usage Guide

Bulkhead is a guardrails engine that detects PII, secrets, prompt injection, and test data in text. It runs as a library, an HTTP server, an MCP server, or a Docker container.

Source: [github.com/floatingsidewal/bulkhead](https://github.com/floatingsidewal/bulkhead)

---

## Install

Bulkhead is published under two scopes. Use whichever fits your environment.

**Public npm (recommended for most users)** -- no `.npmrc` needed:

```bash
npm install @bulkhead-ai/core
npm install @bulkhead-ai/server   # only if you need the HTTP/MCP server
```

**GitHub Packages** -- requires a `.npmrc` pointing the scope at the GitHub registry:

```bash
# .npmrc (project root)
@floatingsidewal:registry=https://npm.pkg.github.com

npm install @floatingsidewal/bulkhead-core
npm install @floatingsidewal/bulkhead-server
```

Use the GitHub Packages scope if you are contributing to Bulkhead or need pre-release builds from `develop`. For everything else, use `@bulkhead-ai`.

All import examples in this guide use `@bulkhead-ai/core`.

---

## Basic Scanning

`createEngine()` returns an engine with PII, secret, and injection guards enabled by default. The regex layer runs in sub-millisecond time.

```typescript
import { createEngine } from "@bulkhead-ai/core";

const engine = createEngine();

// analyze() returns per-guard results
const results = await engine.analyze("Contact me at john.doe@acme.com or call 555-867-5309");

for (const result of results) {
  if (!result.passed) {
    console.log(`${result.guardName}: ${result.reason}`);
    for (const d of result.detections) {
      console.log(`  ${d.entityType} score=${d.score} confidence=${d.confidence} "${d.text}"`);
    }
  }
}
```

`scan()` runs `analyze()` and also produces redacted text:

```typescript
const { passed, results, redactedText } = await engine.scan(
  "My SSN is 078-05-1120 and my key is AKIA1234567890ABCDEF"
);

console.log(passed);        // false
console.log(redactedText);  // "My SSN is [REDACTED-US_SSN] and my key is [REDACTED-AWS_ACCESS_KEY]"
```

### Reading results

Each `GuardResult` contains:

| Field | Type | Meaning |
|-------|------|---------|
| `passed` | `boolean` | `true` if nothing actionable was found |
| `guardName` | `string` | Which guard produced this result (`pii`, `secret`, `injection`, `leakage`, `testdata`) |
| `score` | `number` | Aggregate score (0--1) |
| `detections` | `Detection[]` | Individual findings |
| `redactedText` | `string?` | Text with detections replaced by `[REDACTED-TYPE]` placeholders |

Each `Detection` contains:

| Field | Type | Meaning |
|-------|------|---------|
| `entityType` | `string` | e.g. `US_SSN`, `AWS_ACCESS_KEY`, `CREDIT_CARD` |
| `text` | `string` | The matched text |
| `start` / `end` | `number` | Character offsets |
| `score` | `number` | Detection confidence (0--1) |
| `confidence` | `"high" \| "medium" \| "low"` | Confidence band |
| `source` | `"regex" \| "bert" \| "llm"` | Which cascade layer produced it |
| `disposition` | `"confirmed" \| "escalate" \| "dismissed" \| "informational"` | Cascade decision |

---

## Policy-Based Scanning

Policies bundle guard configuration, risk thresholds, and test data handling into a reusable definition. Bulkhead ships two built-in policies: `strict` and `moderate`.

```typescript
import { createEngine, getPolicy } from "@bulkhead-ai/core";

const engine = createEngine({
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
const { passed, risk, results, redactedText } = await engine.policyScan(
  "Patient Jane Doe, SSN 456-78-9012, prescribed Lisinopril 10mg",
  policy
);

console.log(`Risk level: ${risk.level}`);   // "critical" | "high" | "medium" | "low" | "none"
console.log(`Risk score: ${risk.score}`);   // 0-1
console.log(`Issues: ${risk.issues.length}`);
console.log(`Test data flags: ${risk.testDataFlags.length}`);
```

### Reading RiskAssessment

| Field | Type | Meaning |
|-------|------|---------|
| `level` | `RiskLevel` | Overall risk: `critical`, `high`, `medium`, `low`, or `none` |
| `score` | `number` | Aggregate 0--1 |
| `guards` | `Record<string, { level, score, detectionCount }>` | Per-guard breakdown |
| `issues` | `ClassifiedIssue[]` | Deduplicated issues grouped by category |
| `testDataFlags` | `TestDataFlag[]` | Synthetic data markers |

Each `ClassifiedIssue` includes:

| Field | Type | Meaning |
|-------|------|---------|
| `category` | `"pii" \| "secret" \| "injection" \| "leakage" \| "testdata"` | Issue category |
| `entityType` | `string` | Specific type (e.g. `US_SSN`) |
| `severity` | `RiskLevel` | How severe this issue is |
| `count` | `number` | How many times detected |
| `isTestData` | `boolean` | Whether this overlaps with known test data |
| `sample` | `string?` | First detection text, truncated |

### Strict vs moderate

| Setting | Strict | Moderate |
|---------|--------|----------|
| PII threshold | 0.3 | 0.5 |
| Secret threshold | 0.5 | 0.7 |
| Injection threshold | 0.5 | 0.6 |
| PII mode | `block` | `redact` |
| Secret mode | `block` | `redact` |
| Risk critical threshold | 0.9 | 0.9 |
| Risk high threshold | 0.7 | 0.8 |
| Risk medium threshold | 0.5 | 0.65 |
| Risk low threshold | 0.3 | 0.5 |
| Test data detection | `flag` | `flag` |

Use `strict` for production data pipelines where any leak is unacceptable. Use `moderate` for development workflows where you want warnings without hard blocks.

---

## Test Data Detection

The `TestDataGuard` identifies synthetic, placeholder, and eval data so you can distinguish real sensitive content from fabricated test values.

### What it catches

| Pattern | Examples |
|---------|----------|
| Synthetic GUIDs | GUIDs containing `test`, `eval`, `demo`, `mock`, `fake`, `sample` in their segments; all-zero GUIDs |
| Test credit cards | `4111111111111111` (Visa), `4242424242424242` (Stripe), `5555555555554444` (Mastercard), and others from Stripe/PayPal/Braintree documentation |
| Test SSNs | `000-00-0000`, `123-45-6789`, `078-05-1120` (Woolworth), `219-09-9999` (Social Security ad) |
| Placeholder emails | Addresses at `example.com`, `example.org`, `test.com`, `mailinator.com`, `tempmail.com`; any `noreply@` address |
| Fictional phones | 555-01xx range (reserved by NANPA for fictional use) |
| Sequential patterns | `AAAA000000000001`-style identifiers, `1234567890abcdef` |

### How `isTestData` works

When both a PII guard and the TestDataGuard flag the same text region, the resulting `ClassifiedIssue` has `isTestData: true`. This lets you separate real risk from benign test fixtures in your assessment logic:

```typescript
for (const issue of risk.issues) {
  if (issue.isTestData) {
    console.log(`[test data] ${issue.entityType} x${issue.count} -- safe to ignore`);
  } else {
    console.log(`[real] ${issue.severity} ${issue.entityType} x${issue.count}`);
  }
}
```

### The `testDataDetection` policy setting

| Value | Behavior |
|-------|----------|
| `"flag"` | Detect test data and mark matching issues with `isTestData: true` (default for both built-in policies) |
| `"strip"` | Detect and remove test data detections from the results entirely |
| `"ignore"` | Do not run the TestDataGuard at all |

---

## Custom Guard Composition

You can skip `createEngine()` and build an engine with exactly the guards and entity types you need:

```typescript
import { GuardrailsEngine, PiiGuard, SecretGuard } from "@bulkhead-ai/core";

const engine = new GuardrailsEngine();

// Only scan for credit cards and SSNs
engine.addGuard(new PiiGuard({ entityTypes: ["CREDIT_CARD", "US_SSN"] }));

// Only scan for AWS keys and Stripe keys
engine.addGuard(new SecretGuard({ secretTypes: ["AWS_ACCESS_KEY", "STRIPE_KEY"] }));

const results = await engine.analyze("Card: 4111111111111111, Key: sk_live_abc123def456");
```

You can also combine custom guards with policy scanning:

```typescript
import { GuardrailsEngine, PiiGuard, SecretGuard, TestDataGuard, getPolicy } from "@bulkhead-ai/core";

const engine = new GuardrailsEngine();
engine.addGuard(new PiiGuard({ entityTypes: ["US_SSN", "CREDIT_CARD", "EMAIL_ADDRESS"] }));
engine.addGuard(new SecretGuard());
engine.addGuard(new TestDataGuard());

const policy = getPolicy("moderate");
const { risk } = await engine.policyScan("SSN: 123-45-6789", policy);
// risk.issues[0].isTestData === true (this is a known test SSN)
```

---

## BERT Layer (Optional)

The BERT layer adds a neural NER model as a second classification pass. Detections from the regex layer are confirmed or escalated by the model.

### Setup

Install the transformer runtime (peer dependency, not included by default):

```bash
npm install @huggingface/transformers
```

Enable the BERT layer in your engine config:

```typescript
const engine = createEngine({
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
    modelEnabled: true,
    modelId: "Xenova/bert-base-NER",
  },
});
```

The model downloads (~29 MB) on first use and caches locally. It runs in a worker thread and does not block the main event loop.

### Scanning with BERT

```typescript
// Regex + BERT (no LLM)
const modelResults = await engine.modelScan("Contact Dr. Sarah Chen at 617-555-0142");

// Full cascade: regex + BERT + LLM (requires LLM provider config)
const deepResults = await engine.deepScan("Contact Dr. Sarah Chen at 617-555-0142");
```

Each detection includes a `source` field (`"regex"`, `"bert"`, or `"llm"`) and a `disposition` field (`"confirmed"`, `"escalate"`, or `"dismissed"`) so you can see which layer made the final call.

---

## MCP Integration

Bulkhead exposes three MCP tools: `bulkhead_scan`, `bulkhead_redact`, and `bulkhead_configure`.

### Docker container (recommended for Claude Code)

Add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "bulkhead": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "ghcr.io/floatingsidewal/bulkhead:latest",
        "node", "packages/server/dist/mcp/index.js"
      ]
    }
  }
}
```

### npm binary

If you have the package installed locally:

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

### Available tools

| Tool | Description |
|------|-------------|
| `bulkhead_scan` | Scan text for PII, secrets, and injection. Accepts `text` (string) and `mode` (`"fast"`, `"model"`, or `"deep"`). Returns detections with scores and a cascade layer summary. |
| `bulkhead_redact` | Scan text and return a redacted version with `[REDACTED-TYPE]` placeholders. Accepts `text` (string). |
| `bulkhead_configure` | Enable or disable guards at runtime. Accepts `guards` (e.g. `{ "pii": { "enabled": false } }`). Returns the current active guard list. |

---

## HTTP Server

### Starting the server

**With npm:**

```bash
cd packages/server
npm start
# Bulkhead server listening on 0.0.0.0:3000
```

**With Docker:**

```bash
docker run -p 3000:3000 ghcr.io/floatingsidewal/bulkhead:latest
```

**With environment variables:**

```bash
BULKHEAD_PORT=8080 \
BULKHEAD_API_KEY=my-secret-key \
BULKHEAD_CASCADE_MODEL_ENABLED=true \
npm start
```

### API endpoints

**Scan (regex only, sub-ms):**

```bash
curl -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 456-78-9012 and email is jane@example.com"}'
```

**Deep scan (regex + BERT + LLM):**

```bash
curl -X POST http://localhost:3000/v1/scan/deep \
  -H "Content-Type: application/json" \
  -d '{"text": "Patient record: John Smith, DOB 1985-03-15"}'
```

**Model scan (regex + BERT, no LLM):**

```bash
curl -X POST http://localhost:3000/v1/scan/model \
  -H "Content-Type: application/json" \
  -d '{"text": "AWS key: AKIAIOSFODNN7EXAMPLE"}'
```

**Redact:**

```bash
curl -X POST http://localhost:3000/v1/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Call me at 212-555-1234, my card is 4111111111111111"}'
```

### API key authentication

Set `BULKHEAD_API_KEY` to require an `X-API-Key` header on all scan/redact endpoints:

```bash
BULKHEAD_API_KEY=my-secret-key npm start
```

```bash
curl -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my-secret-key" \
  -d '{"text": "secret content here"}'
```

Health and readiness endpoints are exempt from authentication.

### Health checks

```bash
# Liveness -- always 200 if the process is running
curl http://localhost:3000/healthz

# Readiness -- 200 when engine is ready, 503 while BERT model is loading
curl http://localhost:3000/readyz

# Info -- version, active guards, cascade status
curl http://localhost:3000/v1/info
```

---

## Scenario: Medical Record Scanning

Scan a FHIR-style patient record for HIPAA-sensitive content using a custom policy that targets healthcare-specific entity types.

```typescript
import { createEngine, getPolicy, resolvePolicy } from "@bulkhead-ai/core";
import type { PolicyDefinition } from "@bulkhead-ai/core";

// Define a HIPAA-focused policy
const hipaaPolicy: PolicyDefinition = {
  name: "hipaa",
  description: "HIPAA-focused scanning for protected health information",
  guards: {
    pii: {
      enabled: true,
      threshold: 0.3,
      mode: "block",
      entityTypes: [
        "US_SSN",
        "US_MBI",
        "US_NPI",
        "MEDICAL_LICENSE",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "DATE_TIME",
      ],
    },
    secret: { enabled: true, threshold: 0.5, mode: "block" },
    injection: { enabled: false },
    leakage: { enabled: false },
  },
  riskThresholds: { critical: 0.8, high: 0.6, medium: 0.4, low: 0.2 },
  testDataDetection: "flag",
};

const engine = createEngine({
  enabled: true,
  debounceMs: 0,
  guards: {
    pii: { enabled: true },
    secret: { enabled: true },
    injection: { enabled: false },
    contentSafety: { enabled: false },
  },
  cascade: {
    escalationThreshold: 0.75,
    contextSentences: 3,
    modelEnabled: false,
    modelId: "Xenova/bert-base-NER",
  },
  policy: hipaaPolicy,
});

// A FHIR-style patient record
const patientRecord = JSON.stringify({
  resourceType: "Patient",
  id: "pat-29381",
  name: [{ family: "Ramirez", given: ["Maria", "Elena"] }],
  birthDate: "1987-04-12",
  identifier: [
    { system: "http://hl7.org/fhir/sid/us-ssn", value: "412-68-3190" },
    { system: "http://hospital.example.org/mrn", value: "MRN-20481937" },
  ],
  telecom: [
    { system: "phone", value: "503-284-9173" },
    { system: "email", value: "m.ramirez@gmail.com" },
  ],
  generalPractitioner: [
    { reference: "Practitioner/dr-liu", display: "Dr. Angela Liu, NPI 1234567893" },
  ],
  note: "Patient reports persistent lower back pain. Prescribed Cyclobenzaprine 10mg TID. Follow up in 2 weeks. Diagnosis: M54.5 (low back pain), G89.29 (chronic pain).",
}, null, 2);

// Scan with the HIPAA policy
const { passed, risk, redactedText } = await engine.policyScan(patientRecord, hipaaPolicy);

console.log(`Passed: ${passed}`);
console.log(`Risk: ${risk.level} (score ${risk.score.toFixed(2)})`);

for (const issue of risk.issues) {
  const flag = issue.isTestData ? " [test data]" : "";
  console.log(`  ${issue.severity} ${issue.category}/${issue.entityType} x${issue.count}${flag}`);
  if (issue.sample) {
    console.log(`    sample: "${issue.sample}"`);
  }
}

// The redacted version is safe to store in logs or pass to downstream systems
if (redactedText) {
  console.log("\nRedacted record:");
  console.log(redactedText);
}
```

---

## Scenario: Bulk Data Conversion to Eval Data

Take a dataset of real records, scan each one, redact PII and secrets, and produce a safe dataset suitable for evaluation or testing.

```typescript
import { createEngine, getPolicy } from "@bulkhead-ai/core";
import type { RiskLevel } from "@bulkhead-ai/core";
import { readFileSync, writeFileSync } from "node:fs";

// Sample input: an array of support tickets
interface SupportTicket {
  id: string;
  customerName: string;
  email: string;
  phone: string;
  subject: string;
  body: string;
}

const tickets: SupportTicket[] = JSON.parse(
  readFileSync("./data/support-tickets.json", "utf-8")
);

const engine = createEngine({
  enabled: true,
  debounceMs: 0,
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

// Track statistics
const stats = {
  total: tickets.length,
  withIssues: 0,
  riskDistribution: { critical: 0, high: 0, medium: 0, low: 0, none: 0 } as Record<RiskLevel, number>,
  totalDetections: 0,
};

const redactedTickets: Array<SupportTicket & { _riskLevel: RiskLevel }> = [];

for (const ticket of tickets) {
  // Serialize the full ticket to scan all fields at once
  const fullText = [
    ticket.customerName,
    ticket.email,
    ticket.phone,
    ticket.subject,
    ticket.body,
  ].join("\n");

  const { risk, redactedText } = await engine.policyScan(fullText, policy);

  stats.riskDistribution[risk.level]++;
  stats.totalDetections += risk.issues.reduce((sum, i) => sum + i.count, 0);

  if (risk.issues.length > 0) {
    stats.withIssues++;
  }

  // Split the redacted text back into fields
  const lines = (redactedText ?? fullText).split("\n");

  redactedTickets.push({
    id: ticket.id,
    customerName: lines[0],
    email: lines[1],
    phone: lines[2],
    subject: lines[3],
    body: lines.slice(4).join("\n"),
    _riskLevel: risk.level,
  });
}

// Write the safe dataset
writeFileSync(
  "./data/support-tickets-redacted.json",
  JSON.stringify(redactedTickets, null, 2)
);

// Log statistics
console.log(`Processed ${stats.total} records`);
console.log(`Records with issues: ${stats.withIssues} (${((stats.withIssues / stats.total) * 100).toFixed(1)}%)`);
console.log(`Total detections: ${stats.totalDetections}`);
console.log("Risk distribution:");
for (const [level, count] of Object.entries(stats.riskDistribution)) {
  if (count > 0) {
    console.log(`  ${level}: ${count}`);
  }
}
```

---

## Custom Policies

Define a `PolicyDefinition` to control which guards run, at what thresholds, and how risk levels are calculated.

```typescript
import { createEngine, resolvePolicy } from "@bulkhead-ai/core";
import type { PolicyDefinition } from "@bulkhead-ai/core";

const myPolicy: PolicyDefinition = {
  name: "internal-api",
  description: "Policy for internal API gateway logs",
  guards: {
    pii: {
      enabled: true,
      threshold: 0.4,
      mode: "redact",
      entityTypes: ["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD"],
    },
    secret: {
      enabled: true,
      threshold: 0.6,
      mode: "block",
      secretTypes: ["AWS_ACCESS_KEY", "GITHUB_TOKEN", "GENERIC_API_KEY"],
    },
    injection: { enabled: false },
    leakage: { enabled: false },
  },
  riskThresholds: {
    critical: 0.9,
    high: 0.75,
    medium: 0.5,
    low: 0.3,
  },
  testDataDetection: "strip",
};
```

### Composing policies

`resolvePolicy()` merges a base policy with overlays. The stricter setting wins: lower thresholds, `block` over `redact`, entity type intersection when both specify types.

```typescript
// Start with moderate, overlay a custom restriction
const composed = resolvePolicy("moderate", {
  name: "api-hardened",
  description: "Tighter thresholds for API scanning",
  guards: {
    pii: { threshold: 0.3, mode: "block" },
  },
  riskThresholds: { critical: 0.85, high: 0.7, medium: 0.5, low: 0.3 },
  testDataDetection: "flag",
});

// composed.name === "moderate+api-hardened"
// composed.guards.pii.threshold === 0.3 (stricter wins)
// composed.guards.pii.mode === "block" (block wins over redact)
```

### Available configuration

| Field | Type | Description |
|-------|------|-------------|
| `guards.pii.entityTypes` | `string[]` | Restrict PII detection to these entity types only |
| `guards.secret.secretTypes` | `string[]` | Restrict secret detection to these secret types only |
| `guards.*.threshold` | `number` | Minimum score (0--1) for a detection to count |
| `guards.*.mode` | `"block" \| "redact"` | Whether to block or redact matched content |
| `guards.*.enabled` | `boolean` | Enable or disable the guard |
| `riskThresholds` | `RiskThresholds` | Score boundaries for `critical`, `high`, `medium`, `low` risk levels |
| `testDataDetection` | `"flag" \| "strip" \| "ignore"` | How to handle synthetic data |

---

## Adding New Patterns

### Adding a PII pattern

1. Choose the appropriate regional file in `src/patterns/pii/` (`generic.ts`, `us.ts`, `uk.ts`, `eu.ts`, `apac.ts`).
2. Define the pattern with `entityType`, `patterns` (regex array), optional `validate` function, `contextWords`, `baseConfidence`, and `baseScore`.
3. Export it from the regional patterns array.
4. Add tests in `test/guards/pii.guard.test.ts` and `test/adversarial/adversarial.test.ts`.

See [patterns.md](./patterns.md) for the full pattern definition reference.

### Adding a secret pattern

1. Open `src/patterns/secrets.ts`.
2. Add a `SecretPattern` with `secretType`, `patterns`, and optional `minEntropy`.
3. Add it to `ALL_SECRET_PATTERNS`.
4. Add tests in `test/guards/secret.guard.test.ts`.

### Adding a checksum validator

1. Open `src/validators/checksums.ts`.
2. Add a validation function that takes a string and returns a boolean.
3. Reference it from your pattern's `validate` function to reduce false positives.

---

## Handling False Positives

**Raise thresholds.** Increase the per-guard `threshold` in your policy to require higher confidence before flagging:

```typescript
const policy: PolicyDefinition = {
  name: "lenient-pii",
  description: "Higher threshold to reduce false positives",
  guards: {
    pii: { enabled: true, threshold: 0.7, mode: "redact" },
    secret: { enabled: true, threshold: 0.8, mode: "redact" },
    injection: { enabled: true, threshold: 0.7, mode: "block" },
  },
  riskThresholds: { critical: 0.9, high: 0.8, medium: 0.65, low: 0.5 },
  testDataDetection: "flag",
};
```

**Filter entity types.** Narrow the guard to only the types you care about, which eliminates noise from broad pattern matching:

```typescript
new PiiGuard({ entityTypes: ["US_SSN", "CREDIT_CARD"] })
```

**File as a test case.** Add the false positive to `test/adversarial/adversarial.test.ts` under the "False Positive Resistance" section. This ensures the fix is validated and the false positive does not regress.
