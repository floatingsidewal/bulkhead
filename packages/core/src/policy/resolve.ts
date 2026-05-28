import type { PolicyDefinition, GuardPolicyConfig } from "./types";
import type { PiiGuardOptions } from "../guards/pii.guard";
import type { SecretGuardOptions } from "../guards/secret.guard";
import type { GuardConfig } from "../types";
import { getPolicy } from "./presets";

/**
 * Resolve a policy reference (string name or definition) to a full PolicyDefinition.
 */
export function resolveRef(
  ref: string | PolicyDefinition
): PolicyDefinition {
  return typeof ref === "string" ? getPolicy(ref) : ref;
}

/**
 * Compose policies by merging a base with overlays.
 * "Stricter wins": lower thresholds, entity-type intersection, block over redact.
 */
export function resolvePolicy(
  base: string | PolicyDefinition,
  ...overlays: (string | PolicyDefinition)[]
): PolicyDefinition {
  let result = structuredClone(resolveRef(base));

  for (const overlay of overlays) {
    const o = resolveRef(overlay);
    result = mergePolicies(result, o);
  }

  return result;
}

function mergePolicies(
  base: PolicyDefinition,
  overlay: PolicyDefinition
): PolicyDefinition {
  const result = structuredClone(base);
  result.name = `${base.name}+${overlay.name}`;
  result.description = `${base.description} | ${overlay.description}`;

  // Merge each guard config
  for (const guardName of ["pii", "secret", "injection", "leakage"] as const) {
    const baseGuard = base.guards[guardName];
    const overlayGuard = overlay.guards[guardName];

    if (!overlayGuard) continue;
    if (!baseGuard) {
      result.guards[guardName] = structuredClone(overlayGuard);
      continue;
    }

    result.guards[guardName] = mergeGuardConfig(baseGuard, overlayGuard);
  }

  // Stricter risk thresholds (lower values)
  if (overlay.riskThresholds) {
    result.riskThresholds = {
      critical: Math.min(
        base.riskThresholds.critical,
        overlay.riskThresholds.critical
      ),
      high: Math.min(base.riskThresholds.high, overlay.riskThresholds.high),
      medium: Math.min(
        base.riskThresholds.medium,
        overlay.riskThresholds.medium
      ),
      low: Math.min(base.riskThresholds.low, overlay.riskThresholds.low),
    };
  }

  // Test data: "flag" > "strip" > "ignore"
  if (overlay.testDataDetection) {
    result.testDataDetection = overlay.testDataDetection;
  }

  // Temporal policy: stricter wins.
  //   rebase-relative-to-earliest > rebase-year-zero > preserve > undefined
  // Stricter wins because a more aggressive temporal transformation
  // strictly removes more correlatable signal than a less aggressive one.
  const TEMPORAL_RANK: Record<string, number> = {
    "rebase-relative-to-earliest": 3,
    "rebase-year-zero": 2,
    preserve: 1,
  };
  const baseRank = TEMPORAL_RANK[base.temporalPolicy?.mode ?? "preserve"] ?? 0;
  const overlayRank = TEMPORAL_RANK[overlay.temporalPolicy?.mode ?? "preserve"] ?? 0;
  if (overlayRank > baseRank) {
    result.temporalPolicy = overlay.temporalPolicy;
  } else if (baseRank > overlayRank) {
    result.temporalPolicy = base.temporalPolicy;
  } else {
    // Equal rank: take the lower-precision (stricter) of the two.
    const PREC_RANK: Record<string, number> = { ms: 1, second: 2, minute: 3, hour: 4, day: 5 };
    const basePrec = PREC_RANK[base.temporalPolicy?.precision ?? "ms"] ?? 1;
    const overlayPrec = PREC_RANK[overlay.temporalPolicy?.precision ?? "ms"] ?? 1;
    result.temporalPolicy =
      overlayPrec >= basePrec ? overlay.temporalPolicy : base.temporalPolicy;
  }

  return result;
}

function mergeGuardConfig(
  base: Partial<GuardPolicyConfig>,
  overlay: Partial<GuardPolicyConfig>
): Partial<GuardPolicyConfig> {
  const result: Partial<GuardPolicyConfig> = { ...base };

  // Enabled: if either disables, disabled
  if (overlay.enabled !== undefined) {
    result.enabled = overlay.enabled;
  }

  // Threshold: stricter wins (lower)
  if (overlay.threshold !== undefined) {
    result.threshold =
      base.threshold !== undefined
        ? Math.min(base.threshold, overlay.threshold)
        : overlay.threshold;
  }

  // Mode: stricter wins. block > synthesize > redact.
  if (overlay.mode !== undefined) {
    const order: Record<string, number> = { block: 3, synthesize: 2, redact: 1 };
    const overlayRank = order[overlay.mode] ?? 0;
    const baseRank = order[base.mode ?? "redact"] ?? 0;
    result.mode = overlayRank >= baseRank ? overlay.mode : base.mode!;
  }

  // Entity types: intersection when both specify
  if (overlay.entityTypes) {
    if (base.entityTypes && base.entityTypes.length > 0) {
      const overlaySet = new Set(overlay.entityTypes);
      result.entityTypes = base.entityTypes.filter((t) => overlaySet.has(t));
    } else {
      result.entityTypes = [...overlay.entityTypes];
    }
  }

  // Secret types: same intersection logic
  if (overlay.secretTypes) {
    if (base.secretTypes && base.secretTypes.length > 0) {
      const overlaySet = new Set(overlay.secretTypes);
      result.secretTypes = base.secretTypes.filter((t) => overlaySet.has(t));
    } else {
      result.secretTypes = [...overlay.secretTypes];
    }
  }

  return result;
}

/** Translate a resolved policy into guard constructor options and per-guard configs */
export function policyToEngineConfig(policy: PolicyDefinition): {
  piiOptions: PiiGuardOptions;
  secretOptions: SecretGuardOptions;
  guardConfigs: Record<string, Partial<GuardConfig>>;
} {
  const pii = policy.guards.pii ?? {};
  const secret = policy.guards.secret ?? {};
  const injection = policy.guards.injection ?? {};
  const leakage = policy.guards.leakage ?? {};

  return {
    piiOptions: {
      entityTypes: pii.entityTypes,
    },
    secretOptions: {
      secretTypes: secret.secretTypes,
    },
    guardConfigs: {
      pii: { threshold: pii.threshold, mode: pii.mode },
      secret: { threshold: secret.threshold, mode: secret.mode },
      injection: { threshold: injection.threshold, mode: injection.mode },
      leakage: { threshold: leakage.threshold, mode: leakage.mode },
      testdata: { mode: policy.testDataDetection === "strip" ? "redact" : "block" },
    },
  };
}
