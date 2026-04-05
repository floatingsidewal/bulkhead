/** Confidence level for a detection */
export type Confidence = "high" | "medium" | "low";

/** A detected entity in text */
export interface Detection {
  /** Entity type (e.g., "CREDIT_CARD", "US_SSN", "AWS_KEY") */
  entityType: string;
  /** Start offset in the input text */
  start: number;
  /** End offset in the input text */
  end: number;
  /** The matched text */
  text: string;
  /** Detection confidence */
  confidence: Confidence;
  /** Numeric score 0-1 */
  score: number;
  /** Which guard produced this detection */
  guardName: string;
}

/** Result from a single guard's analysis */
export interface GuardResult {
  /** Whether the text passed this guard (no issues found) */
  passed: boolean;
  /** Human-readable reason for the result */
  reason: string;
  /** Name of the guard that produced this result */
  guardName: string;
  /** Overall score 0-1 (0 = safe, 1 = maximum threat) */
  score: number;
  /** Individual detections found */
  detections: Detection[];
  /** Modified text with redactions applied (if applicable) */
  redactedText?: string;
}

/** Guard mode: block rejects the input, redact sanitizes it */
export type GuardMode = "block" | "redact";

/** Configuration for a guard */
export interface GuardConfig {
  /** Whether this guard is enabled */
  enabled: boolean;
  /** Detection threshold 0-1 (detections below this score are ignored) */
  threshold: number;
  /** What to do when a detection occurs */
  mode: GuardMode;
}

/** A guard analyzes text and returns results */
export interface Guard {
  /** Unique name for this guard */
  readonly name: string;
  /** Analyze text and return results */
  analyze(text: string, config?: Partial<GuardConfig>): Promise<GuardResult>;
}

/** Configuration for the guardrails engine */
export interface EngineConfig {
  /** Guard-specific configuration overrides */
  guards: Record<string, Partial<GuardConfig>>;
}

/** A PII pattern definition */
export interface PiiPattern {
  /** Entity type name (e.g., "CREDIT_CARD") */
  entityType: string;
  /** Regex patterns to match */
  patterns: RegExp[];
  /** Optional validation function (e.g., Luhn check) */
  validate?: (match: string) => boolean;
  /** Context words that boost confidence when found nearby */
  contextWords?: string[];
  /** Base confidence without context boost */
  baseConfidence: Confidence;
  /** Base score without context boost */
  baseScore: number;
}

/** A secret pattern definition */
export interface SecretPattern {
  /** Secret type name (e.g., "AWS_ACCESS_KEY") */
  secretType: string;
  /** Regex patterns to match */
  patterns: RegExp[];
  /** Optional validation function */
  validate?: (match: string) => boolean;
  /** Minimum entropy threshold (if applicable) */
  minEntropy?: number;
}

/** Tactic names for detection strategies */
export type TacticName = "pattern" | "heuristic" | "llm";

/** Result from a tactic execution */
export interface TacticResult {
  /** Score 0-1 */
  score: number;
  /** Additional context about the detection */
  details?: Record<string, unknown>;
}

/** A detection tactic */
export interface Tactic {
  readonly name: TacticName;
  readonly defaultThreshold: number;
  execute(input: string): Promise<TacticResult>;
}
