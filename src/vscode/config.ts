import * as vscode from "vscode";

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

export function getConfig(): BulkheadConfig {
  const cfg = vscode.workspace.getConfiguration("bulkhead");
  return {
    enabled: cfg.get("enabled", true),
    debounceMs: cfg.get("debounceMs", 500),
    guards: {
      pii: { enabled: cfg.get("guards.pii.enabled", true) },
      secret: { enabled: cfg.get("guards.secret.enabled", true) },
      injection: { enabled: cfg.get("guards.injection.enabled", true) },
      contentSafety: { enabled: cfg.get("guards.contentSafety.enabled", false) },
    },
    cascade: {
      escalationThreshold: cfg.get("cascade.escalationThreshold", 0.75),
      contextSentences: cfg.get("cascade.contextSentences", 3),
      modelEnabled: cfg.get("cascade.modelEnabled", false),
      modelId: cfg.get(
        "cascade.modelId",
        "gravitee-io/bert-small-pii-detection"
      ),
    },
  };
}
