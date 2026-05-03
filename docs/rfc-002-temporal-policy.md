# RFC-002: Temporal Policy for Date / Timestamp Sanitization

**Status:** Proposed
**Phase:** 6 (Sanitization & Privacy Modes)
**Tracks:** Policy System, PII Patterns

## Summary

Add a `temporalPolicy` field to `PolicyDefinition` that controls how detected dates and timestamps are transformed. Three modes:

- **`preserve`** (default; current behavior) — dates pass through unchanged.
- **`rebase-year-zero`** — replace the year in any ISO 8601 / mm-dd-yyyy / yyyy-mm-dd timestamp with `0001`, preserving month, day, and time-of-day.
- **`rebase-relative-to-earliest`** — find the earliest timestamp in the input, anchor everything relative to `0001-01-01T00:00:00Z`, preserve relative offsets in milliseconds.

This RFC depends on RFC-001 (synthesize mode) for its replacement mechanism: temporal-policy rewrites are emitted as redactions just like PII synthesis, with full provenance through the redaction map.

## Motivation

Bulkhead detects `DATE_TIME` today (`packages/core/src/patterns/pii/generic.ts:133`) at low confidence (score 0.30). Detection is the easy part; the hard question is **what to do with detected dates** when the consumer's privacy goal is "no real timestamps."

The current options:

- `mode: "redact"` → `[REDACTED-DATE_TIME]`. Loses temporal ordering. Breaks downstream consumers that need to reason about case age, transfer sequencing, etc.
- `mode: "preserve"` (effectively, by setting `enabled: false` for DATE_TIME) → leaks real dates. A 2026-Q2 ticket and a 2024-Q1 ticket are visibly distinguishable; combined with other low-entropy signals this is enough for re-identification.

Neither is right for the **eval-corpus** scenario where:

1. The corpus must be safe to commit to git (no real dates that correlate to incidents, support engineer schedules, social-media posts, etc.).
2. Downstream consumers (LLM evaluations, replay tooling) must still see **valid, totally-ordered ISO 8601 timestamps** so date arithmetic works.
3. Relative offsets matter — "transfer happened 2.1 hours after creation" is signal that an eval might want to use; absolute `2026-04-30T10:00:00Z` is leak.

Both `rebase-year-zero` and `rebase-relative-to-earliest` solve this; they differ on whether year-of-month-of-day-of-week patterns are preserved or fully anchored.

### Non-goals

- Replacing parsable dates inside free prose ("the customer reported on April 30, 2026"). That's a content-classification problem better solved by the PERSON_NAME-style entity detection: free-text prose dates would need a higher-confidence pattern + LLM disambiguation, and the consumer ships them through `mode: "synthesize"` to get something like "April 30, year zero" or "<DATE>". This RFC focuses on **structured timestamp fields**.
- Computing relative offsets across multiple `engine.scan()` calls. Cross-call temporal consistency requires the consumer to manage anchoring (analogous to RFC-001 Q3).

## Proposed API

### 1. New types

```ts
// packages/core/src/policy/types.ts

/**
 * How to handle detected dates and timestamps. Default is "preserve"
 * (current behavior; emits low-score detections only, no transformation).
 */
export type TemporalMode =
  | "preserve"
  | "rebase-year-zero"
  | "rebase-relative-to-earliest";

export interface TemporalPolicy {
  mode: TemporalMode;
  /**
   * If true, year-zero / relative rebasing applies to ALL detected dates
   * regardless of the DATE_TIME guard's threshold. If false (default),
   * only detections that pass the guard threshold are rebased.
   */
  forceAll?: boolean;
  /**
   * Whether to round rebased timestamps to a coarser unit. Defaults to
   * "ms" (preserve full precision). Set "hour" or "day" for additional
   * privacy at cost of relative-ordering precision.
   */
  precision?: "ms" | "second" | "minute" | "hour" | "day";
}
```

### 2. `PolicyDefinition` extension

```ts
// packages/core/src/policy/types.ts

export interface PolicyDefinition {
  // ... existing fields
  /** How to transform detected timestamps. Default: { mode: "preserve" }. */
  temporalPolicy?: TemporalPolicy;
}
```

### 3. Built-in preset additions

```ts
// packages/core/src/policy/presets.ts

// `strict` policy gains:
//   temporalPolicy: { mode: "rebase-year-zero" }
// (Strict already blocks PII; rebasing dates is consistent with that posture.)

// `moderate` policy gains:
//   temporalPolicy: { mode: "preserve" }
// (Explicit, matches current behavior.)

// New `eval` policy (proposed in RFC-001):
//   temporalPolicy: { mode: "rebase-relative-to-earliest", precision: "ms" }
// (Eval needs realistic relative timing, anchored to a synthetic origin.)
```

### 4. Implementation hook

The temporal-policy transformation runs **as part of the existing `applyRedactions` step** (extended in RFC-001). For each `DATE_TIME` detection:

```ts
// packages/core/src/guards/temporal.ts (new)

export function applyTemporalPolicy(
  text: string,
  detections: Detection[],
  policy: TemporalPolicy,
  consistencyMap: Map<string, string>
): { text: string; redactions: RedactionEntry[] } {
  const dateDetections = detections.filter(d => d.entityType === "DATE_TIME");
  if (policy.mode === "preserve" || dateDetections.length === 0) {
    return { text, redactions: [] };
  }

  // Mode "rebase-year-zero":  for each detection, parse, replace year with 0001, format back.
  // Mode "rebase-relative-to-earliest":
  //   1. Parse all detections, sort, take earliest as anchor.
  //   2. For each, compute (parsed - anchor) as ms delta.
  //   3. Output = "0001-01-01T00:00:00.000Z" + delta, formatted as ISO 8601.
  // Apply precision rounding before formatting.
  // Build replacements via the standard reverse-sorted slice-and-replace.
}
```

The hook is **purely additive** — it runs after the cascade, before the standard redaction-application step.

## Why year `0001` and not `0000`?

- ECMAScript `Date` accepts `"0001-01-01T00:00:00Z"` and round-trips correctly.
- ECMAScript `Date` accepts `"0000-01-01"` historically, but specification footnotes describe year-zero handling as implementation-defined; some libraries reject it.
- ISO 8601 itself permits year `0000`, but most date-handling libraries normalize it to `1 BC` and back, which is fragile.
- Year `0001` is unambiguous, format-compatible, and obviously synthetic to a human reading the data.

This matches the convention adopted by Microsoft Presidio and other PII-redaction toolkits.

## Worked examples

### Example A: `rebase-year-zero`

```
Input:    Case 12345 created 2026-04-30T05:37:33Z, transferred 2026-05-01T11:00:00Z.
Output:   Case 12345 created 0001-04-30T05:37:33Z, transferred 0001-05-01T11:00:00Z.
```

Preserves: month, day, hour, minute, second, day-of-week relationship, time-of-day patterns.
Removes: year, calendar epoch correlations.

### Example B: `rebase-relative-to-earliest`

```
Input timestamps:
  - 2026-04-30T05:37:33.000Z   (earliest)
  - 2026-04-30T11:00:00.000Z   (+5h22m27s)
  - 2026-05-02T18:40:59.000Z   (+62h3m26s)

Output timestamps:
  - 0001-01-01T00:00:00.000Z
  - 0001-01-01T05:22:27.000Z
  - 0001-01-03T18:03:26.000Z
```

Preserves: relative offsets in milliseconds.
Removes: year, month, day, time-of-day patterns.

## Risk vs. policy interaction

When `temporalPolicy` is set on a policy AND a `DATE_TIME` guard is enabled (or detected via the always-on regex layer), both run. The temporal transformation overrides whatever `mode` was configured for `DATE_TIME` (which would be `redact` or `synthesize`).

Resolution rule when policies are merged:

```
preserve < rebase-year-zero < rebase-relative-to-earliest
```

Stricter wins, matching the existing policy-resolver convention (see `packages/core/src/policy/resolve.ts`).

## Open questions

### Q1. Detection-only vs. all-timestamps

Two reasonable scopes:

**Option A (proposed):** Only transform timestamps that the `DATE_TIME` guard detected. Keeps the mechanism unified with the rest of the cascade. Risk: low-confidence near-misses get preserved.

**Option B:** Sweep the input text with a year-only regex (`\b\d{4}\b` near a date-shaped neighbor) regardless of the guard. More aggressive, but lower false-negative rate.

Recommendation: **Option A.** Bulkhead's contract is "what the cascade detected, the cascade transforms." If the consumer wants more aggressive sweeping they can lower the `DATE_TIME` threshold. Option B can be added later as `forceAll: true` (already in the proposed type) without breaking change.

### Q2. Date formats other than ISO 8601

The existing `DATE_TIME` pattern matches three families:

```js
// ISO 8601:     2026-04-30T05:37:33Z
// US format:    04/30/2026 (or 30/04/2026)
// Hyphenated:   2026-04-30
```

For `rebase-year-zero`, all three are easy: regex-replace year-position digits with `0001`.

For `rebase-relative-to-earliest`, all three need to **parse to a reference point**, which is fragile for `04/30/2026` (ambiguous mm/dd vs dd/mm).

Recommendation: For `rebase-relative-to-earliest`, restrict to ISO 8601 timestamps only. Other formats are passed through unchanged with a warning entry in the redaction map (`via: "skipped-unparseable-format"`). This matches Bulkhead's general posture of conservative, explainable transformations.

### Q3. Should `harvestedAt`-style metadata fields participate?

When the consumer is producing structured records (eg. via `scanObject` from RFC-001+), there will be metadata fields (`harvestedAt`, `extractedAt`, etc.) that aren't in the case content but **are** real timestamps that re-identify the harvest run.

**Recommendation:** out of scope for this RFC. The structured-data caller (consumer of `scanObject`) is responsible for choosing which paths get fed through bulkhead and which are passed-through metadata. This RFC governs what bulkhead does with detected timestamps; metadata choices belong to the consumer.

### Q4. Time-zone handling

ISO 8601 timestamps may carry an offset (`+05:30`, `Z`, etc.). Should rebasing normalize to UTC?

**Proposal:** Normalize to UTC. Year-zero and relative-rebased timestamps always emit `Z`. Reasoning: timezone is signal that can correlate to customer location; preserving it defeats the privacy goal.

### Q5. Default for new patterns

When future versions add new `DATE_TIME` patterns (eg. RFC 2822, Unix epoch seconds), the default policy is `preserve` so new detections do not surprise existing consumers. Strict / eval presets pick up the new patterns automatically because they request rebasing of all detected dates.

## Migration

Purely additive. Existing consumers see no change unless they explicitly set `temporalPolicy`.

Existing presets are updated to make their temporal posture explicit:

- `strict` gains `temporalPolicy: { mode: "rebase-year-zero" }`. **Behavior change** for strict consumers — but consistent with strict's existing "block on PII" stance, and well within the policy's documented sensitivity. Worth calling out in the changelog.
- `moderate` gains `temporalPolicy: { mode: "preserve" }`. **No behavior change** — explicitness only.
- `eval` (new) is opt-in.

## Testing strategy

Per CONTRIBUTING.md:

1. **Positive:** `rebase-year-zero` rewrites `2026-04-30T05:37:33Z` to `0001-04-30T05:37:33Z`.
2. **Positive:** `rebase-relative-to-earliest` produces correctly-anchored output for a multi-timestamp input.
3. **Negative:** input with no detected dates passes through unchanged.
4. **Negative:** mode `preserve` is a no-op even if `DATE_TIME` detections exist.
5. **False-positive:** a 4-digit number that *isn't* in date context (eg. `port 2026`) is not rewritten.
6. **Adversarial:** mixed ISO 8601 + US-format input — only ISO entries get rebased in `rebase-relative-to-earliest`, others fall through with redaction-map warnings.
7. **Adversarial:** total ordering of timestamps preserved by both rebase modes.
8. **Round-trip:** rebased timestamps parse back correctly via `new Date(...)`.
9. **Consistency:** within-call, the same input timestamp produces the same output (trivially true for both modes since they're pure functions, but worth asserting).

## Implementation plan

Lands as a separate PR after RFC approval.

Estimated work:

1. Type additions (~20 lines)
2. `applyTemporalPolicy` function in `packages/core/src/guards/temporal.ts` (~120 lines including parsing)
3. Engine wiring to call temporal transformation in the redact/synthesize pipeline (~30 lines)
4. Preset updates (~10 lines)
5. Tests (~250 lines)
6. Documentation (`docs/policy.md`, `docs/api.md`)

Total: 1 day of focused work.

## Relationship to RFC-001

This RFC is **complementary** to RFC-001 but does not strictly require it. Without RFC-001, `temporalPolicy` works as a separate transformation pass before the standard `redact` step. With RFC-001, the temporal transformation flows through the same redaction-map machinery for unified provenance.

Recommended landing order:

1. RFC-001 implementation lands first (provides `redactionMap` plumbing).
2. RFC-002 implementation reuses that plumbing for temporal redactions.

If the maintainer prefers, RFC-002 could land first with its own redaction-map (to be merged with RFC-001's later). The shape is small enough that either order works.
