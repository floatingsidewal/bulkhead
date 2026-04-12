// Core engine
import { GuardrailsEngine } from "./engine/engine";
export { GuardrailsEngine } from "./engine/engine";

// Guards
import { PiiGuard } from "./guards/pii.guard";
import { SecretGuard } from "./guards/secret.guard";
import { InjectionGuard } from "./guards/injection.guard";
import { LeakageGuard } from "./guards/leakage.guard";
import { TestDataGuard } from "./guards/testdata.guard";
export { BaseGuard } from "./guards/base.guard";
export { PiiGuard } from "./guards/pii.guard";
export type { PiiGuardOptions } from "./guards/pii.guard";
export { SecretGuard } from "./guards/secret.guard";
export type { SecretGuardOptions } from "./guards/secret.guard";
export { InjectionGuard } from "./guards/injection.guard";
export { LeakageGuard } from "./guards/leakage.guard";
export { TestDataGuard } from "./guards/testdata.guard";

// Types
export type {
  Detection,
  GuardResult,
  Guard,
  GuardConfig,
  GuardMode,
  EngineConfig,
  Confidence,
  DetectionSource,
  Disposition,
  PiiPattern,
  SecretPattern,
  TacticName,
  TacticResult,
  Tactic,
} from "./types";

// Cascade types re-exported for config convenience
export type { CascadeConfig } from "./cascade/cascade";
export type { BertLayerConfig } from "./cascade/bert-layer";
export type { LlmProvider, LlmLayerConfig } from "./cascade/llm-layer";

// Policy system
export {
  BUILTIN_POLICIES,
  getPolicy,
  resolvePolicy,
  policyToEngineConfig,
  assessRisk,
} from "./policy";
export type {
  RiskLevel,
  GuardPolicyConfig,
  RiskThresholds,
  PolicyDefinition,
  RiskAssessment,
  ClassifiedIssue,
  TestDataFlag,
} from "./policy";

// Policy-aware engine creation
import { resolveRef, resolvePolicy, policyToEngineConfig } from "./policy";
import type { PolicyDefinition } from "./policy";

// Platform-neutral config interface
export interface BulkheadConfig {
  enabled: boolean;
  debounceMs: number;
  guards: {
    pii: { enabled: boolean };
    secret: { enabled: boolean };
    injection: { enabled: boolean };
    contentSafety: { enabled: boolean };
  };
  cascade: {
    escalationThreshold: number;
    contextSentences: number;
    modelEnabled: boolean;
    modelId: string;
  };
  /** Named policy or custom PolicyDefinition. Overrides guard-level config. */
  policy?: string | PolicyDefinition;
  /** Additional policy overlays for composition */
  policyOverlays?: (string | PolicyDefinition)[];
}

export const DEFAULT_CONFIG: BulkheadConfig = {
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
};

/** Create a configured engine from a BulkheadConfig */
export function createEngine(config: BulkheadConfig = DEFAULT_CONFIG): GuardrailsEngine {
  const engine = new GuardrailsEngine();

  // If a policy is specified, resolve it and derive guard options
  if (config.policy) {
    let policy = resolveRef(config.policy);
    if (config.policyOverlays && config.policyOverlays.length > 0) {
      policy = resolvePolicy(policy, ...config.policyOverlays);
    }

    const { piiOptions, secretOptions, guardConfigs } = policyToEngineConfig(policy);

    if (policy.guards.pii?.enabled !== false) {
      engine.addGuard(new PiiGuard(piiOptions));
    }
    if (policy.guards.secret?.enabled !== false) {
      engine.addGuard(new SecretGuard(secretOptions));
    }
    if (policy.guards.injection?.enabled !== false) {
      engine.addGuard(new InjectionGuard());
      engine.addGuard(new LeakageGuard());
    }
    if (policy.testDataDetection !== "ignore") {
      engine.addGuard(new TestDataGuard());
    }

    engine.updateConfig({ guards: guardConfigs });
  } else {
    // Legacy path: use config.guards directly
    if (config.guards.pii.enabled) {
      engine.addGuard(new PiiGuard());
    }
    if (config.guards.secret.enabled) {
      engine.addGuard(new SecretGuard());
    }
    if (config.guards.injection.enabled) {
      engine.addGuard(new InjectionGuard());
      engine.addGuard(new LeakageGuard());
    }
  }

  if (config.cascade.modelEnabled) {
    engine.initCascade({
      bertEnabled: true,
      llmEnabled: config.guards.contentSafety.enabled,
      escalationThreshold: config.cascade.escalationThreshold,
      contextSentences: config.cascade.contextSentences,
      modelId: config.cascade.modelId,
    });
  }

  return engine;
}
