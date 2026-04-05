import type {
  Guard,
  GuardResult,
  GuardConfig,
  Detection,
  GuardMode,
} from "../types";

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
