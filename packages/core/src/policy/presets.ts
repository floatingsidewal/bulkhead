import type { PolicyDefinition } from "./types";

/** Strict policy: flag everything, low thresholds, block mode */
const STRICT: PolicyDefinition = {
  name: "strict",
  description:
    "Maximum sensitivity — flags all detectable PII, secrets, injection, and test data at low confidence thresholds",
  guards: {
    pii: { enabled: true, threshold: 0.3, mode: "block" },
    secret: { enabled: true, threshold: 0.5, mode: "block" },
    injection: { enabled: true, threshold: 0.5, mode: "block" },
    leakage: { enabled: true, threshold: 0.5, mode: "block" },
  },
  riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
  testDataDetection: "flag",
};

/** Moderate policy: reasonable defaults, higher thresholds, redact mode */
const MODERATE: PolicyDefinition = {
  name: "moderate",
  description:
    "Balanced sensitivity — flags high-confidence PII and secrets, redacts rather than blocks",
  guards: {
    pii: { enabled: true, threshold: 0.5, mode: "redact" },
    secret: { enabled: true, threshold: 0.7, mode: "redact" },
    injection: { enabled: true, threshold: 0.6, mode: "block" },
    leakage: { enabled: true, threshold: 0.6, mode: "block" },
  },
  riskThresholds: { critical: 0.9, high: 0.8, medium: 0.65, low: 0.5 },
  testDataDetection: "flag",
};

/** All built-in policies indexed by name */
export const BUILTIN_POLICIES: Record<string, PolicyDefinition> = {
  strict: STRICT,
  moderate: MODERATE,
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
