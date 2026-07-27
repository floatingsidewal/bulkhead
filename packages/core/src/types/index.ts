/** Confidence level for a detection */
export type Confidence = "high" | "medium" | "low";

/** Which cascade layer produced this detection */
export type DetectionSource = "regex" | "bert" | "llm";

/** Whether this detection is final or needs escalation */
export type Disposition = "confirmed" | "escalate" | "dismissed" | "informational";

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
  /** Matched heuristic keyword, when applicable */
  matchedKeyword?: string;
  /** Which cascade layer produced this detection */
  source: DetectionSource;
  /** Surrounding text window for context */
  context: string;
  /** Whether this detection is final or needs escalation */
  disposition: Disposition;
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
  /**
   * Per-detection record of original → replacement, in document order.
   * Populated when the guard ran in mode `redact` or `synthesize`. Each
   * entry includes the entity type and whether the replacement came
   * from a synthesizer or the placeholder fallback.
   */
  redactionMap?: RedactionEntry[];
}

/**
 * Guard mode:
 *  - `block`:      input is rejected (passed: false, no transformation).
 *  - `redact`:     detected entities are replaced with `[REDACTED-TYPE]`.
 *  - `synthesize`: detected entities are replaced with realistic synthetic
 *                  values from the engine's SynthesizerRegistry. Within one
 *                  scan call, the same original value maps to the same
 *                  synthetic value (consistency map).
 *
 * Stricter wins in policy merge: block > synthesize > redact.
 */
export type GuardMode = "block" | "redact" | "synthesize";

/**
 * One row in a guard's redaction map. Records the original detected text,
 * the replacement value emitted, the entity type, and which strategy
 * produced the replacement.
 */
export interface RedactionEntry {
  /** The original (detected) value as it appeared in the input. */
  original: string;
  /** The value substituted into the redacted output. */
  replacement: string;
  /** The entity type from the underlying detection. */
  entityType: string;
  /**
   * How the replacement was produced:
   *  - `placeholder`: the standard `[REDACTED-TYPE]` form.
   *  - `synthesizer`: a synthesizer (default or user-registered) emitted
   *                   a realistic value.
   */
  via: "placeholder" | "synthesizer";
}

/**
 * Per-call context passed to a Synthesizer.
 *
 * The `consistencyMap` is shared across every detection in one scan call
 * (and across guards within that call). Synthesizers read from it before
 * generating new values so the same original always produces the same
 * synthetic replacement within one document.
 */
export interface SynthesizerContext {
  /** The detection that produced this call. */
  detection: Detection;
  /**
   * Within-call original→replacement map. Synthesizers should consult
   * this before generating new output. The engine writes back to it
   * automatically after the synthesizer returns.
   */
  consistencyMap: Map<string, string>;
}

/**
 * Produce a synthetic replacement for one detected entity.
 *
 * Pure function. Must NOT call back into the engine. Sync by default;
 * async is allowed for synthesizers that consult external registries.
 */
export type Synthesizer = (
  original: string,
  ctx: SynthesizerContext,
) => string | Promise<string>;

/** Configuration for a guard */
export interface GuardConfig {
  /** Whether this guard is enabled */
  enabled: boolean;
  /** Detection threshold 0-1 (detections below this score are ignored) */
  threshold: number;
  /** What to do when a detection occurs */
  mode: GuardMode;
}

/**
 * Per-call context for redaction / synthesis. The engine constructs this
 * once per `scan()` call so all guards share a synthesizer registry and
 * consistency map.
 *
 * Type is opaque here to avoid a circular import; the implementation
 * lives in `synthesizers/registry.ts`.
 */
export interface RedactContext {
  /** Engine-supplied SynthesizerRegistry. */
  registry?: {
    get(entityType: string): Synthesizer | undefined;
    has(entityType: string): boolean;
  };
  /** Within-call original→replacement map shared across guards. */
  consistencyMap?: Map<string, string>;
}

/** A guard analyzes text and returns results */
export interface Guard {
  /** Unique name for this guard */
  readonly name: string;
  /**
   * Analyze text and return results.
   *
   * The optional `redactCtx` parameter is supplied by the engine when
   * one or more guards may run in `mode: "synthesize"`. It carries the
   * shared SynthesizerRegistry and the per-call consistency map so that
   * detections of the same value across multiple guards collapse to the
   * same synthetic replacement. Existing callers that pass only
   * (text, config) continue to work — synthesize mode without a
   * registry falls back to placeholder replacement.
   */
  analyze(
    text: string,
    config?: Partial<GuardConfig>,
    redactCtx?: RedactContext,
  ): Promise<GuardResult>;
}

/** Configuration for the guardrails engine */
export interface EngineConfig {
  /** Guard-specific configuration overrides */
  guards: Record<string, Partial<GuardConfig>>;
}

/**
 * Result of `engine.scanObject()`. Mirrors `engine.scan()` but adds a
 * `redactedObject` field that preserves the input shape and a
 * `pathDetections` map keyed by JSON path so consumers can locate
 * detections within nested structures without re-walking.
 */
export interface ObjectScanResult<T> {
  /** True iff every string leaf passed every enabled guard. */
  passed: boolean;
  /** Aggregate per-guard results, with detections accumulated across all leaves. */
  results: GuardResult[];
  /**
   * Input with all string leaves replaced by their guard-redacted form
   * where applicable. Non-string leaves (numbers, booleans, null,
   * undefined, Date, RegExp, …) pass through unchanged. Object key
   * order is preserved; array length is preserved.
   */
  redactedObject: T;
  /**
   * JSON-style path → detections found at that leaf. Paths use dot
   * notation for object keys and `[i]` for array indices, matching the
   * conventional JS-debugger style. The root path is the empty string.
   *
   * Example keys:
   *   ""           — root (only if root itself is a string)
   *   "title"      — top-level field
   *   "history[0].sapPath" — array element field
   *
   * Only paths where ≥1 detection occurred appear in this map.
   */
  pathDetections: Record<string, Detection[]>;
}

/** A value that can be represented without loss in JSON. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/** How slash-delimited localized dates are interpreted. */
export type LocalizedDateOrder = "mdy" | "dmy" | "reject-ambiguous";

/** Options specific to one document sanitization call. */
export interface SanitizeDocumentOptions {
  /** Interpretation for localized four-digit-year dates. Defaults to reject ambiguous dates. */
  localizedDateOrder?: LocalizedDateOrder;
  /** Replacement for a detected date that cannot be parsed safely. */
  detectedUnparseableDateReplacement?: string;
  /** Reserved for callers that need to make a call's clock explicit. */
  now?: Date;
}

/** A detection before treatment, located in the logical JSON document. */
export interface DetectionSummary {
  category: string;
  sourcePath: string;
  sourceSpan?: { start: number; end: number };
  treatment: "replaced" | "rebased" | "merged-redaction" | "untreated";
}

/** Risk that remained after reconstruction. */
export interface ResidualFinding {
  category: string;
  path: string;
  reason: "surviving-source-value" | "untreated-detection";
}

/** Pre-treatment risk and the result of the final logical safety check. */
export interface TreatmentMetadata {
  detectedRisk: {
    count: number;
    categories: Record<string, number>;
    detections: DetectionSummary[];
  };
  postTreatment: {
    safe: boolean;
    residuals: ResidualFinding[];
    structurallyValid: boolean;
  };
  temporalAnchor?: string;
  /** Collision-safe keys emitted while preserving all original object entries. */
  keyCollisions?: Array<{ path: string; replacement: string }>;
}

/** Result of object-native document sanitization. */
export interface SanitizeResult<T extends JsonValue> {
  value: T;
  metadata: TreatmentMetadata;
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
  /** Context words that boost confidence when found nearby (e.g., ["heroku", "api_key"]) */
  contextWords?: string[];
  /** Base score without context boost (0-1). Defaults to 0.9 if unset. */
  baseScore?: number;
  /** Base confidence without context boost. Defaults to "high" if unset. */
  baseConfidence?: Confidence;
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
