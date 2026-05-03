import type { PolicyDefinition } from "./types";

/** Strict policy: flag everything, low thresholds, block mode */
const STRICT: PolicyDefinition = {
  name: "strict",
  description:
    "Maximum sensitivity — flags all detectable PII, secrets, injection, and test data at low confidence thresholds. Rebases timestamps to year-zero so leaked dates cannot correlate to incident timelines.",
  guards: {
    pii: { enabled: true, threshold: 0.3, mode: "block" },
    secret: { enabled: true, threshold: 0.5, mode: "block" },
    injection: { enabled: true, threshold: 0.5, mode: "block" },
    leakage: { enabled: true, threshold: 0.5, mode: "block" },
  },
  riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
  testDataDetection: "flag",
  temporalPolicy: { mode: "rebase-year-zero" },
};

/** Moderate policy: reasonable defaults, higher thresholds, redact mode */
const MODERATE: PolicyDefinition = {
  name: "moderate",
  description:
    "Balanced sensitivity — flags high-confidence PII and secrets, redacts rather than blocks. Preserves timestamps as-is.",
  guards: {
    pii: { enabled: true, threshold: 0.5, mode: "redact" },
    secret: { enabled: true, threshold: 0.7, mode: "redact" },
    injection: { enabled: true, threshold: 0.6, mode: "block" },
    leakage: { enabled: true, threshold: 0.6, mode: "block" },
  },
  riskThresholds: { critical: 0.9, high: 0.8, medium: 0.65, low: 0.5 },
  testDataDetection: "flag",
  temporalPolicy: { mode: "preserve" },
};

/**
 * Eval policy: synthesize realistic replacements for downstream eval /
 * training corpora. Detects at moderate thresholds, replaces detected
 * PII and secrets with synthesizer-supplied realistic values rather
 * than `[REDACTED-TYPE]` placeholders so the output reads like a real
 * document. Injection and leakage stay redacted (those should be
 * obviously marked, not synthesized into something plausible).
 *
 * Temporal: timestamps are anchored to year-zero with offsets relative
 * to the earliest detected timestamp. Preserves relative timing
 * (intervals, ordering) for downstream analysis while removing all
 * year/month/day correlation that could re-identify incidents.
 *
 * Use when producing privacy-safe but content-realistic eval inputs.
 */
const EVAL_POLICY: PolicyDefinition = {
  name: "eval",
  description:
    "Synthesize realistic replacements for PII and secrets so sanitized content reads like a real document. Best for eval corpora and training datasets. Timestamps are rebased to year-zero relative offsets.",
  guards: {
    pii: { enabled: true, threshold: 0.5, mode: "synthesize" },
    secret: { enabled: true, threshold: 0.7, mode: "synthesize" },
    injection: { enabled: true, threshold: 0.7, mode: "redact" },
    leakage: { enabled: true, threshold: 0.7, mode: "redact" },
  },
  riskThresholds: { critical: 0.9, high: 0.8, medium: 0.65, low: 0.5 },
  testDataDetection: "flag",
  temporalPolicy: { mode: "rebase-relative-to-earliest", precision: "ms" },
};

/** All built-in policies indexed by name */
export const BUILTIN_POLICIES: Record<string, PolicyDefinition> = {
  strict: STRICT,
  moderate: MODERATE,
  eval: EVAL_POLICY,
};

/** Retrieve a built-in policy by name */
export function getPolicy(name: string): PolicyDefinition {
  const policy = BUILTIN_POLICIES[name];
  if (!policy) {
    const available = Object.keys(BUILTIN_POLICIES).join(", ");
    throw new Error(
      `Unknown policy "${name}". Available: ${available}`
    );
  }
  return policy;
}
