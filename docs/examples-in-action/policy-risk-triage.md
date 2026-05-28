# Demo: Policy-Based Risk Triage (Block vs Redact)

## Goal

Use `policyScan` with built-in policies to classify risk and choose whether to block, redact, or allow a payload.

## Scenario

An internal tool routes content differently based on risk:

- `critical` / `high`: block
- `medium`: redact then send
- `low` / `none`: allow

## 1) Use strict policy in an app flow

```typescript
import { createEngine, getPolicy } from "@bulkhead-ai/core";

const engine = createEngine({ policy: "strict" });
const policy = getPolicy("strict");

const input = "Patient: Jane Doe, SSN 219-09-9999, email jane.doe@example.com";
const { risk, redactedText } = await engine.policyScan(input, policy);

if (risk.level === "critical" || risk.level === "high") {
  console.log("BLOCK", risk.issues);
} else if (risk.level === "medium") {
  console.log("REDACT_AND_SEND", redactedText);
} else {
  console.log("ALLOW");
}
```

## 2) What to expect

`policyScan` returns a structured risk decision surface:

- `risk.level` and `risk.score`
- `risk.issues` grouped by category/entity type
- `risk.testDataFlags` for synthetic fixture awareness
- `redactedText` when redaction mode applies

## 3) Swap policy by environment

- Production or regulated pipeline: `strict`
- Developer workflow with lower friction: `moderate`

This gives the same engine two operating modes without rewriting business logic.

## Why this works end-to-end

Policies convert raw detections into action-ready risk levels, so downstream systems can make consistent block/redact/allow decisions automatically.
