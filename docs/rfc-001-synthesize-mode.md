# RFC-001: Synthesize Mode for Guards

**Status:** Proposed
**Phase:** 6 (Sanitization & Privacy Modes)
**Tracks:** Engine API, Policy System

## Summary

Add a third guard mode, `mode: "synthesize"`, that replaces detected entities with **realistic synthetic values** rather than `[REDACTED-TYPE]` placeholders. The engine carries a per-call **consistency map** so that the same original input always maps to the same synthetic output within one scan. Bulkhead ships **default synthesizers** for common entity types; consumers can override or extend them.

## Motivation

Today's `mode: "redact"` rewrites detections to placeholders (`[REDACTED-EMAIL_ADDRESS]`, `[REDACTED-PERSON_NAME]`, ...). This is correct for two scenarios:

- **Pre-LLM-call sanitization in IDE workflows**, where the LLM only needs to understand "there is an email here" and shouldn't see the real value.
- **Compliance scrubbing**, where the priority is "no PII left" rather than "downstream consumers see realistic data."

It is **insufficient** for a third scenario: producing **sanitized eval / training corpora** where downstream consumers (model evaluations, demos, bug reproductions, public datasets) need content that *reads like a real document*. A triage skill being evaluated against a sanitized case cannot tell whether `[REDACTED-PERSON_NAME] is frustrated` is one customer or five different customers, and outputs that reference the placeholder verbatim are visibly broken.

The standard fix in PII tooling is to replace detections with realistic synthetic values from a curated registry. This RFC adds that capability to Bulkhead in a way that composes with the existing cascade and policy system.

### Non-goals

- Producing privacy-safe synthetic *datasets* from scratch. Bulkhead synthesizes individual values found by its detectors; building synthetic-first generation pipelines is out of scope.
- Reversibility. The redaction map records `original → replacement`, but Bulkhead does not retain a way to map backwards once the call returns.
- Differential privacy guarantees. Synthetic values are realistic-looking; they are not noise-injected for DP compliance.

## Proposed API

### 1. `GuardMode` extension

```ts
// packages/core/src/types/index.ts

/** Guard mode: block rejects, redact replaces with [REDACTED-TYPE], synthesize replaces with realistic equivalents. */
export type GuardMode = "block" | "redact" | "synthesize";
```

### 2. Synthesizer signature

```ts
// packages/core/src/types/index.ts

export interface SynthesizerContext {
  /** The detection that produced this call (for entity-type, score, source provenance). */
  detection: Detection;
  /** Within-call consistency map; synthesizer may seed it but usually reads from it. */
  consistencyMap: Map<string, string>;
  /** Optional caller-supplied seed for deterministic output. */
  seed?: string;
}

/**
 * Produce a synthetic replacement for one detected entity.
 * Pure function. Must NOT call back into the engine.
 *
 * Default synthesizers ship with Bulkhead; consumers register overrides
 * via SynthesizerRegistry.
 */
export type Synthesizer = (original: string, ctx: SynthesizerContext) => string;

export interface SynthesizerRegistry {
  /** Register a synthesizer for a specific entity type. Replaces any default. */
  set(entityType: string, fn: Synthesizer): this;
  /** Look up the synthesizer for an entity type, falling back to defaults. */
  get(entityType: string): Synthesizer | undefined;
  /** Bulk-register multiple synthesizers. */
  setMany(synths: Record<string, Synthesizer>): this;
}
```

### 3. Engine wiring

```ts
// packages/core/src/engine/engine.ts

export class GuardrailsEngine {
  // ... existing
  /** Replaces / merges over the default synthesizer registry. */
  setSynthesizers(synths: Record<string, Synthesizer>): this;

  /** Look up the active registry (defaults + user-registered). */
  get synthesizers(): SynthesizerRegistry;
}
```

### 4. `applyRedactions` becomes mode-aware

```ts
// packages/core/src/guards/base.guard.ts

protected applyRedactions(
  text: string,
  detections: Detection[],
  mode: GuardMode,
  registry: SynthesizerRegistry,
  consistencyMap: Map<string, string>
): { text: string; redactionMap: RedactionEntry[] } {
  // Sort detections by start desc so replacements don't shift offsets.
  // For each detection:
  //   - mode "redact":     replacement = `[REDACTED-${entityType}]`
  //   - mode "synthesize": replacement = consistencyMap.get(original)
  //                          ?? registry.get(entityType)?.(original, ctx)
  //                          ?? `[REDACTED-${entityType}]`  // graceful fallback
  // Always cache replacement into consistencyMap before reuse.
  // Always emit a RedactionEntry { original, replacement, entityType, source }.
}

export interface RedactionEntry {
  original: string;
  replacement: string;
  entityType: string;
  /** Whether the replacement came from a synthesizer or the placeholder fallback. */
  via: "synthesizer" | "placeholder";
}
```

### 5. `GuardResult` carries a redaction map

```ts
export interface GuardResult {
  // ... existing
  /** Modified text with redactions applied (when mode != "block"). */
  redactedText?: string;
  /** Per-detection record of original → replacement, in document order. */
  redactionMap?: RedactionEntry[];
}
```

The engine's aggregate `scan` result accumulates `redactionMap` across guards.

## Default synthesizers

Bulkhead ships defaults for the following entity types. Consumers may override any of them; consumers can also register synthesizers for entity types not in this list (synthesizers are keyed by `entityType` string).

| Entity type | Default synthesizer | Example |
|---|---|---|
| `EMAIL_ADDRESS` | Drawn from a stable name list, joined with `@example.com` | `john.smith@contoso.com` → `alex.rivera@example.com` |
| `PERSON_NAME` | Drawn from a stable name list of 50+ first/last combinations | `Vamshi Kumar` → `Jordan Chen` |
| `US_PHONE` / `PHONE_NUMBER` | `+1-555-010-XXXX` (last 4 hashed from input for stability) | `(415) 555-1234` → `+1-555-010-7421` |
| `CREDIT_CARD` | Stripe-published test number matching the detected card brand | (real Visa) → `4242424242424242` |
| `IP_ADDRESS` | RFC 5737 documentation prefix (`192.0.2.X`, `198.51.100.X`) | `203.0.113.42` → `192.0.2.18` |
| `URL` | Replace host with `example.com`, preserve path | `https://customer.real.com/x` → `https://example.com/x` |
| `IBAN_CODE` | `GB82 WEST 1234 5698 7654 32` (well-known IBAN test value) | (real IBAN) → `GB82 WEST 1234 5698 7654 32` |
| `MAC_ADDRESS` | `00:00:5E:00:53:XX` (RFC 5612 documentation MAC) | (real MAC) → `00:00:5E:00:53:7A` |
| `GUID` | `00000000-redacted-XXXX-0000-NNNNNNNNNNNN` | (real GUID) → `00000000-redacted-0001-0000-...` |

All defaults follow these rules:

1. **Use IETF / RFC documentation reservations where they exist** (example.com, 192.0.2.0/24, RFC 5612 MAC, GB82 IBAN, Stripe test cards). These are guaranteed safe and identifiable as test data.
2. **Stable across calls within one engine instance** via the consistency map.
3. **No randomness without an explicit seed.** Output is deterministic given input + registry. Use cases that need per-document stable IDs (hashes) supply a seed.

### Default name list

A deterministic name list used by the `PERSON_NAME` and `EMAIL_ADDRESS` defaults. Same inputs across versions produce same outputs (frozen list). The list will be 50+ first names / 50+ last names to avoid collisions on small documents; the synthesizer picks via a hash of the original.

## Consistency contract

Within a single `engine.scan(text)` call:

> If `original` appears in the input N times and the synthesizer is invoked N times, the replacement value is identical for all N.

Implementation: a `Map<string, string>` is created per call, seeded by reading existing entries before writing new ones. The map is exposed via `SynthesizerContext.consistencyMap` so custom synthesizers can participate.

Across multiple `engine.scan()` calls, consistency is **not** guaranteed unless the consumer:

- Passes a stable seed via engine config, OR
- Pre-populates the consistency map at engine creation time (advanced use case)

This matches the existing semantics of `[REDACTED-TYPE]` placeholders (which are also fresh per-call) and avoids leaking information across documents.

## Risk vs. policy interaction

`mode: "synthesize"` is treated as **stricter than `redact`** in policy resolution:

```
block > synthesize > redact
```

The reasoning: synthesize is "I will actively rewrite content," redact is "I will mark content but preserve structure for downstream judgment." A consumer that requested `synthesize` (most informational, content modified) is asking for more aggressive transformation than a consumer that requested `redact`.

Existing presets keep their current modes (`strict: block`, `moderate: redact`). A new `eval` preset proposed:

```ts
export const evalPolicy: PolicyDefinition = {
  name: "eval",
  description: "Synthesize all detected PII for downstream eval / training datasets.",
  guards: {
    pii: { enabled: true, threshold: 0.5, mode: "synthesize" },
    secret: { enabled: true, threshold: 0.7, mode: "synthesize" },
    injection: { enabled: true, threshold: 0.7, mode: "redact" },
    leakage: { enabled: true, threshold: 0.7, mode: "redact" },
  },
  riskThresholds: DEFAULT_THRESHOLDS,
  testDataDetection: "flag",
};
```

## Open questions

### Q1. Default synthesizers in core or in a sibling package?

**Option A (proposed):** Ship in `packages/core/src/synthesizers/defaults.ts`. Always available. ~1KB of strings.

**Option B:** Ship in `packages/core/src/synthesizers/` but guarded behind an explicit `engine.useDefaultSynthesizers()` call so unused consumers don't pay for the name list.

Recommendation: **Option A.** Strings are tiny, the consumer footprint is unaffected, and bundlers tree-shake unused string constants in any case. Simplicity wins.

### Q2. What happens when a detection has no synthesizer?

Two reasonable behaviors:

**Option A (proposed):** Fall back to `[REDACTED-${entityType}]` and emit a `via: "placeholder"` redaction-map entry. Never fails.

**Option B:** Throw an error (`UnknownEntityTypeError`). Consumer must register a synthesizer for every detected entity type.

Recommendation: **Option A.** Matches the "best-effort" spirit of redact mode and avoids surprising failures when new patterns are added to bulkhead-io. The redaction map carries enough information for the consumer to detect placeholder fallbacks if they care.

### Q3. Cross-call consistency

If a consumer runs `engine.scan` 1000 times in a harvest loop, should `john@x.com` map to the same replacement across all 1000 calls?

**Default proposal:** No — fresh consistency map per call, matches `mode: "redact"` semantics, no risk of leaking cross-document correlations.

**Opt-in via engine config:**

```ts
engine.setSynthesizers({...}, { sharedConsistencyMap: true });
```

When opt-in, the engine retains the map for the lifetime of the engine. Consumers needing this guarantee (eg. eval-corpus harvesters where the same team should map to the same synthetic team across all cases) opt in explicitly.

### Q4. Synthesizer signature: sync or async?

Defaults are sync (pure functions, no I/O). Custom synthesizers might want to be async (eg. consult a remote registry).

**Proposal:** Allow async via `Synthesizer = (original, ctx) => string | Promise<string>`. The engine `await`s. Adds ~zero overhead when all synthesizers are sync (Promise.resolve is fast and tree-shakable when V8 sees no awaits).

## Migration

This is **purely additive**. Existing consumers who use `mode: "redact"` see no behavioral change. The new mode is opt-in.

`GuardResult.redactionMap` is a new optional field. Existing consumers ignore it.

## Testing strategy

Per CONTRIBUTING.md, every new behavior gets:

1. **Positive test:** synthesize mode produces a replacement matching the entity-type's expected synthetic format.
2. **Negative test:** synthesize mode preserves text outside detections exactly.
3. **False-positive test:** synthesize on input with no detections returns input unchanged.
4. **Adversarial test:** within-document consistency holds across many detections of the same value.
5. **Adversarial test:** custom synthesizer override beats default.
6. **Performance test:** synthesize-mode latency is comparable to redact-mode (~+10% for the registry lookup; well under 1ms per detection).

Plus integration tests through `policyScan` with the new `eval` preset.

## Implementation plan

This RFC proposes the design. Implementation lands as a separate PR after RFC approval.

Estimated work:

1. Type additions in `packages/core/src/types/index.ts` (~30 lines)
2. `SynthesizerRegistry` class + default synthesizers (~200 lines, including the name list)
3. `applyRedactions` mode-aware refactor in `packages/core/src/guards/base.guard.ts` (~50 lines net)
4. Engine plumbing (`packages/core/src/engine/engine.ts`) (~30 lines)
5. New `eval` preset in `packages/core/src/policy/presets.ts` (~15 lines)
6. Tests (~300 lines across `packages/core/test/`)
7. Documentation updates (`docs/policy.md`, `docs/guards.md`, `docs/api.md`)

Total: 1-2 days of focused work.
