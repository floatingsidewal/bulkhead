import type {
  Guard,
  GuardResult,
  GuardConfig,
  Detection,
  GuardMode,
  DetectionSource,
  Disposition,
} from "../types";

const CONTEXT_RADIUS = 150;

const DEFAULT_CONFIG: GuardConfig = {
  enabled: true,
  threshold: 0.5,
  mode: "redact",
};

/** Base class for guards that detect patterns in text */
export abstract class BaseGuard implements Guard {
  abstract readonly name: string;

  protected mergeConfig(config?: Partial<GuardConfig>): GuardConfig {
    return { ...DEFAULT_CONFIG, ...config };
  }

  abstract analyze(
    text: string,
    config?: Partial<GuardConfig>
  ): Promise<GuardResult>;

  /** Build a GuardResult from detections */
  protected buildResult(
    text: string,
    detections: Detection[],
    mode: GuardMode
  ): GuardResult {
    const passed = detections.length === 0;
    const score =
      detections.length > 0
        ? Math.max(...detections.map((d) => d.score))
        : 0;

    let reason: string;
    if (passed) {
      reason = "No issues detected";
    } else {
      const types = [...new Set(detections.map((d) => d.entityType))];
      reason = `Detected: ${types.join(", ")}`;
    }

    const result: GuardResult = {
      passed,
      reason,
      guardName: this.name,
      score,
      detections,
    };

    if (mode === "redact" && !passed) {
      result.redactedText = this.applyRedactions(text, detections);
    }

    return result;
  }

  /** Extract surrounding context for a detection */
  protected extractContext(
    text: string,
    start: number,
    end: number
  ): string {
    const ctxStart = Math.max(0, start - CONTEXT_RADIUS);
    const ctxEnd = Math.min(text.length, end + CONTEXT_RADIUS);
    return text.slice(ctxStart, ctxEnd);
  }

  /** Create a detection with provenance fields pre-filled for regex source */
  protected makeDetection(
    text: string,
    partial: Omit<Detection, "source" | "context" | "disposition">,
    source: DetectionSource = "regex",
    disposition: Disposition = "confirmed"
  ): Detection {
    return {
      ...partial,
      source,
      context: this.extractContext(text, partial.start, partial.end),
      disposition,
    };
  }

  /** Replace detected text with [REDACTED-TYPE] markers */
  protected applyRedactions(text: string, detections: Detection[]): string {
    // Sort detections by start position descending so replacements don't shift offsets
    const sorted = [...detections].sort((a, b) => b.start - a.start);
    let result = text;
    for (const detection of sorted) {
      const replacement = `[REDACTED-${detection.entityType}]`;
      result =
        result.slice(0, detection.start) +
        replacement +
        result.slice(detection.end);
    }
    return result;
  }
}
