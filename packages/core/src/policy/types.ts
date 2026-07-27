import type { GuardMode } from "../types";
import type { LocalizedDateOrder } from "../types";

/** Severity level for risk rating */
export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";

/**
 * How to handle detected dates and timestamps. Default is "preserve"
 * (current behavior; emits low-score detections only, no transformation).
 *
 * - "preserve":             dates pass through unchanged
 * - "rebase-year-zero":     replace the year in any ISO 8601 / mm-dd-yyyy /
 *                            yyyy-mm-dd timestamp with `0001`, preserving
 *                            month, day, and time-of-day. Removes year-of-
 *                            event correlation while keeping seasonality
 *                            and time-of-day patterns.
 * - "rebase-relative-to-earliest":
 *                            find the earliest detected timestamp in the
 *                            input, rebase everything so the earliest
 *                            becomes `0001-01-01T00:00:00.000Z` and all
 *                            others are relative offsets. Removes all
 *                            absolute-time correlation while preserving
 *                            relative timing (intervals, ordering).
 */
export type TemporalMode =
  | "preserve"
  | "rebase-year-zero"
  | "rebase-relative-to-earliest";

/**
 * Temporal policy applied to detected timestamps. See TemporalMode for
 * the available modes. When `mode` is `"preserve"` (default), no
 * transformation runs.
 */
export interface TemporalPolicy {
  mode: TemporalMode;
  /**
   * Round rebased timestamps to a coarser unit. Defaults to "ms"
   * (preserve full precision). Set "hour" or "day" for additional
   * privacy at the cost of relative-ordering precision.
   */
  precision?: "ms" | "second" | "minute" | "hour" | "day";
}

/** Per-guard policy configuration */
export interface GuardPolicyConfig {
  enabled: boolean;
  threshold: number;
  mode: GuardMode;
  /** For PiiGuard: which entity types to detect */
  entityTypes?: string[];
  /** For SecretGuard: which secret types to detect */
  secretTypes?: string[];
  /**
   * Entity types to exclude from remediation (redaction/synthesis).
   * Excluded entities are still detected and reported in results,
   * but are NOT redacted or synthesized — original text is preserved.
   * Useful for preserving technical identifiers (GUIDs, timestamps)
   * while sanitizing personal PII.
   */
  excludeEntities?: string[];
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
  /**
   * Optional temporal-policy transformation applied to detected
   * timestamps. Default: { mode: "preserve" } (no transformation).
   * See TemporalPolicy and TemporalMode.
   */
  temporalPolicy?: TemporalPolicy;
  /** Interpretation for localized dates in document-level sanitization. */
  localizedDateOrder?: LocalizedDateOrder;
  /** Safe replacement for a detected date that cannot be parsed. */
  detectedUnparseableDateReplacement?: string;
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
