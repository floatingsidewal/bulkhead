# Policy Guide

Policies control what Bulkhead looks for and how strictly it rates risk. A policy bundles guard configuration, detection thresholds, risk rating thresholds, and test data handling into a single named profile.

## Built-in Policies

| Policy | PII Threshold | Secret Threshold | Mode | Test Data |
|--------|--------------|-----------------|------|-----------|
| `strict` | 0.3 | 0.5 | block | flag |
| `moderate` | 0.5 | 0.7 | redact | flag |

### Strict

Maximum sensitivity. Flags everything at low confidence thresholds. Best for pre-production audits, compliance checks, or when scanning untrusted input.

### Moderate

Balanced defaults. Higher thresholds reduce false positives. Redacts rather than blocks. Best for runtime scanning where you want to sanitize content without hard failures.

## Using Policies

### With createEngine

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
```

When `policy` is set, it overrides the per-guard config with the policy's thresholds and modes. The `guards.*.enabled` fields in the base config are ignored in favor of the policy definition.

The policy also adds the **TestDataGuard** automatically (unless `testDataDetection: "ignore"` is set).

### policyScan

The `policyScan` method returns both standard guard results AND a risk assessment:

```typescript
const policy = getPolicy("strict");
const { passed, risk, results, redactedText } = await engine.policyScan(text, policy);
```

## Risk Assessment

The `RiskAssessment` object provides:

```typescript
interface RiskAssessment {
  level: "critical" | "high" | "medium" | "low" | "none";
  score: number;           // 0-1 aggregate (max across real detections)
  guards: Record<string, {
    level: RiskLevel;
    score: number;
    detectionCount: number;
  }>;
  issues: ClassifiedIssue[];
  testDataFlags: TestDataFlag[];
}
```

### Risk Levels

Risk levels are determined by the policy's `riskThresholds`:

**Strict policy:**
| Score | Level |
|-------|-------|
| >= 0.9 | critical |
| >= 0.7 | high |
| >= 0.5 | medium |
| >= 0.3 | low |
| < 0.3 | none |

**Moderate policy:**
| Score | Level |
|-------|-------|
| >= 0.9 | critical |
| >= 0.8 | high |
| >= 0.65 | medium |
| >= 0.5 | low |
| < 0.5 | none |

### Classified Issues

Each issue groups detections by guard and entity type:

```typescript
interface ClassifiedIssue {
  category: "pii" | "secret" | "injection" | "leakage" | "testdata";
  entityType: string;    // e.g., "US_SSN", "AWS_ACCESS_KEY"
  severity: RiskLevel;
  count: number;         // how many times detected
  isTestData: boolean;   // overlaps with test data detection
  sample?: string;       // first 50 chars of matched text
}
```

Issues are sorted by severity (critical first), then by count.

## Test Data Detection

The TestDataGuard identifies synthetic, evaluation, and placeholder data. This is **informational only** -- it never blocks or affects the pass/fail result. It helps consumers distinguish real sensitive data from fabricated test fixtures.

### What It Detects

| Entity Type | Pattern | Example |
|-------------|---------|---------|
| `TEST_DATA_GUID` | GUIDs with `eval`, `test`, `demo`, `mock`, `fake` keywords or zero-padded segments | `00000000-eval-0005-0000-000000000001` |
| `TEST_DATA_CREDIT_CARD` | Well-known test card numbers (Visa, Stripe, Amex, Mastercard, Discover) | `4111111111111111`, `4242424242424242` |
| `TEST_DATA_SSN` | Known invalid/reserved SSNs | `123-45-6789`, `000-00-0000` |
| `TEST_DATA_EMAIL` | Placeholder domains | `user@example.com`, `noreply@company.com` |
| `TEST_DATA_PHONE` | Reserved fictional range (555-01xx) | `555-0100` through `555-0199` |
| `TEST_DATA_SEQUENTIAL` | Repetitive hex patterns in IDs | `AAAA000000000001` |

### Cross-Referencing

When the same text span is flagged by both a real guard (PII, secrets) AND the TestDataGuard, the classified issue is annotated with `isTestData: true`. This lets consumers decide whether to:

- **Ignore it** -- it's clearly test data, not a real risk
- **Escalate it** -- test data shouldn't be in production payloads
- **Report it** -- flag for data quality review

### Configuration

The `testDataDetection` field on a policy controls behavior:

| Value | Behavior |
|-------|----------|
| `"flag"` (default) | Run TestDataGuard, include flags in assessment |
| `"strip"` | Run TestDataGuard, exclude overlapping issues from risk score |
| `"ignore"` | Don't run TestDataGuard at all |

## Policy Composition

Policies can be composed with overlays for compliance or domain-specific tuning:

```typescript
import { resolvePolicy } from "@bulkhead-ai/core";

// Start with strict, narrow to PCI-relevant entity types
const pciOverlay: PolicyDefinition = {
  name: "pci-dss",
  description: "PCI-DSS: payment card data focus",
  guards: {
    pii: {
      entityTypes: ["CREDIT_CARD", "US_BANK_NUMBER", "ABA_ROUTING_NUMBER", "IBAN_CODE"],
      threshold: 0.2,
    },
    secret: {
      secretTypes: ["STRIPE_KEY", "SQUARE_ACCESS_TOKEN", "PAYPAL_CLIENT_SECRET", "BRAINTREE_KEY"],
    },
  },
  riskThresholds: { critical: 0.8, high: 0.6, medium: 0.4, low: 0.2 },
};

const resolved = resolvePolicy("strict", pciOverlay);
// resolved.guards.pii.threshold = min(0.3, 0.2) = 0.2
// resolved.guards.pii.entityTypes = ["CREDIT_CARD", "US_BANK_NUMBER", ...]
```

### Composition Rules

- **Thresholds**: Stricter (lower) value wins
- **Entity types**: Intersection when both sides specify a list
- **Mode**: `"block"` wins over `"redact"`
- **Risk thresholds**: Stricter (lower) values win

## Example: Scanning a Support Ticket

```typescript
import { createEngine, getPolicy } from "@bulkhead-ai/core";
import type { RiskAssessment } from "@bulkhead-ai/core";

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

// Scan a JSON support ticket (stringify it)
const ticket = {
  incidentid: "00000000-eval-0002-0000-000000000001",
  ticketnumber: "2604120030000099",
  customerStatement: "I am a student and I'm facing a billing issue...",
  // ...
};

const { risk } = await engine.policyScan(JSON.stringify(ticket), policy);

console.log(`Overall risk: ${risk.level} (${risk.score})`);

// Show real issues
for (const issue of risk.issues) {
  if (issue.isTestData) {
    console.log(`  [TEST DATA] ${issue.entityType} x${issue.count} -- likely synthetic`);
  } else {
    console.log(`  ${issue.severity.toUpperCase()} ${issue.entityType} x${issue.count}`);
  }
}

// Show test data flags
if (risk.testDataFlags.length > 0) {
  console.log(`\nTest data detected (${risk.testDataFlags.length} flags):`);
  for (const flag of risk.testDataFlags) {
    console.log(`  ${flag.reason}: "${flag.value}"`);
  }
}
```

## Custom Policies

Define your own policy to match your domain:

```typescript
import type { PolicyDefinition } from "@bulkhead-ai/core";

const myPolicy: PolicyDefinition = {
  name: "support-conductor",
  description: "Tuned for Azure support ticket scanning",
  guards: {
    pii: { enabled: true, threshold: 0.4, mode: "redact" },
    secret: { enabled: true, threshold: 0.6, mode: "block" },
    injection: { enabled: true, threshold: 0.5, mode: "block" },
    leakage: { enabled: false },
  },
  riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
  testDataDetection: "flag",
};

const engine = createEngine({ ...defaults, policy: myPolicy });
```
