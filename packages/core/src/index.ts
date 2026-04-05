// Core engine
import { GuardrailsEngine } from "./engine/engine";
export { GuardrailsEngine } from "./engine/engine";

// Guards
import { PiiGuard } from "./guards/pii.guard";
import { SecretGuard } from "./guards/secret.guard";
import { InjectionGuard } from "./guards/injection.guard";
import { LeakageGuard } from "./guards/leakage.guard";
export { BaseGuard } from "./guards/base.guard";
export { PiiGuard } from "./guards/pii.guard";
export { SecretGuard } from "./guards/secret.guard";
export { InjectionGuard } from "./guards/injection.guard";
export { LeakageGuard } from "./guards/leakage.guard";

// Cascade
export { CascadeClassifier } from "./cascade/cascade";
export { BertLayer } from "./cascade/bert-layer";
export { LlmLayer } from "./cascade/llm-layer";

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

export type { CascadeConfig } from "./cascade/cascade";
export type { BertLayerConfig } from "./cascade/bert-layer";
export type { LlmProvider, LlmLayerConfig } from "./cascade/llm-layer";

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
    modelId: "gravitee-io/bert-small-pii-detection",
  },
};

/** Create a configured engine from a BulkheadConfig */
export function createEngine(config: BulkheadConfig = DEFAULT_CONFIG): GuardrailsEngine {
  const engine = new GuardrailsEngine();

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
