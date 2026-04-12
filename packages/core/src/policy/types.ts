import type { GuardMode } from "../types";

/** Severity level for risk rating */
export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";

/** Per-guard policy configuration */
export interface GuardPolicyConfig {
  enabled: boolean;
  threshold: number;
  mode: GuardMode;
  /** For PiiGuard: which entity types to detect */
  entityTypes?: string[];
  /** For SecretGuard: which secret types to detect */
  secretTypes?: string[];
}

/** Score thresholds that map aggregate scores to risk levels */
export interface RiskThresholds {
  /** Score >= this is critical */
  critical: number;
  /** Score >= this is high */
  high: number;
  /** Score >= this is medium */
  medium: number;
  /** Score >= this is low; below is none */
  low: number;
}

/** A complete policy definition */
export interface PolicyDefinition {
  name: string;
  description: string;
  guards: {
    pii?: Partial<GuardPolicyConfig>;
    secret?: Partial<GuardPolicyConfig>;
    injection?: Partial<GuardPolicyConfig>;
    leakage?: Partial<GuardPolicyConfig>;
  };
  riskThresholds: RiskThresholds;
  /** How to handle test/synthetic data detection */
  testDataDetection?: "flag" | "strip" | "ignore";
}

/** Risk assessment returned alongside scan results */
export interface RiskAssessment {
  /** Overall risk level */
  level: RiskLevel;
  /** Aggregate score 0-1 */
  score: number;
  /** Per-guard risk breakdown */
  guards: Record<
    string,
    { level: RiskLevel; score: number; detectionCount: number }
  >;
  /** Classified issues grouped by category */
  issues: ClassifiedIssue[];
  /** Synthetic/eval data flags */
  testDataFlags: TestDataFlag[];
}

/** A single classified issue derived from detections */
export interface ClassifiedIssue {
  category: "pii" | "secret" | "injection" | "leakage" | "testdata";
  entityType: string;
  severity: RiskLevel;
  count: number;
  /** Whether this issue overlaps with detected test data */
  isTestData: boolean;
  /** Representative sample (first detection text, truncated) */
  sample?: string;
}

/** A flagged piece of synthetic/test data */
export interface TestDataFlag {
  /** JSON path if available (e.g., "issueContext.SubscriptionID") */
  field?: string;
  /** The flagged value */
  value: string;
  /** Why it was flagged */
  reason: string;
  start: number;
  end: number;
}
