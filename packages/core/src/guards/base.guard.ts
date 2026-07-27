import type {
  Guard,
  GuardResult,
  GuardConfig,
  Detection,
  GuardMode,
  DetectionSource,
  Disposition,
  RedactionEntry,
  Synthesizer,
  SynthesizerContext,
  RedactContext,
} from "../types";

const CONTEXT_RADIUS = 150;

const DEFAULT_CONFIG: GuardConfig = {
  enabled: true,
  threshold: 0.5,
  mode: "redact",
};

/** Re-export for guard subclasses (kept for backwards compat). */
export type { RedactContext };

/** Plan one replacement without mutating a source string. */
export async function planReplacement(
  detection: Detection,
  mode: GuardMode,
  redactCtx?: RedactContext,
): Promise<RedactionEntry> {
  const consistencyMap = redactCtx?.consistencyMap ?? new Map<string, string>();
  const registry = redactCtx?.registry;
  const cached = consistencyMap.get(detection.text);
  if (cached) {
    return {
      original: detection.text,
      replacement: cached,
      entityType: detection.entityType,
      via: cached === `[REDACTED-${detection.entityType}]` ? "placeholder" : "synthesizer",
    };
  }
  if (mode === "synthesize" && registry) {
    const synth: Synthesizer | undefined = registry.get(detection.entityType);
    if (synth) {
      const ctx: SynthesizerContext = { detection, consistencyMap };
      const replacement = await synth(detection.text, ctx);
      consistencyMap.set(detection.text, replacement);
      return {
        original: detection.text,
        replacement,
        entityType: detection.entityType,
        via: "synthesizer",
      };
    }
  }
  const replacement = `[REDACTED-${detection.entityType}]`;
  consistencyMap.set(detection.text, replacement);
  return {
    original: detection.text,
    replacement,
    entityType: detection.entityType,
    via: "placeholder",
  };
}

/** Base class for guards that detect patterns in text */
export abstract class BaseGuard implements Guard {
  abstract readonly name: string;

  protected mergeConfig(config?: Partial<GuardConfig>): GuardConfig {
    return { ...DEFAULT_CONFIG, ...config };
  }

  abstract analyze(
    text: string,
    config?: Partial<GuardConfig>,
  ): Promise<GuardResult>;

  /**
   * Build a GuardResult from detections. Mode-aware:
   *
   *   - `block`:      no transformation; passed=false on any detection.
   *   - `redact`:     each detection replaced by `[REDACTED-TYPE]`.
   *   - `synthesize`: each detection passed to the registry's synthesizer
   *                   for its entityType. Falls back to placeholder if no
   *                   synthesizer is registered. Same `original` always
   *                   produces the same replacement within the call (via
   *                   `consistencyMap`).
   *
   * The optional `redactCtx` parameter is supplied by the engine to share
   * the registry and consistency map across guards in one scan call.
   * When omitted, synthesize mode behaves identically to redact mode (no
   * registered synthesizers are visible without an engine-supplied
   * registry, so all replacements fall back to placeholders).
   */
  protected async buildResult(
    text: string,
    detections: Detection[],
    mode: GuardMode,
    redactCtx?: RedactContext,
  ): Promise<GuardResult> {
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

    // Produce redactedText for any mode with detections.
    // - "redact"/"synthesize": passed=false, redactedText populated (primary use case)
    // - "block": passed=false, redactedText also populated so consumers that
    //   prefer redaction over blocking can use it (e.g., SafeWright output protection)
    if (!passed) {
      const redactMode = mode === "synthesize" ? "synthesize" : "redact";
      const applied = await this.applyRedactions(text, detections, redactMode, redactCtx);
      result.redactedText = applied.text;
      result.redactionMap = applied.redactionMap;
    }

    return result;
  }

  /** Extract surrounding context for a detection */
  protected extractContext(
    text: string,
    start: number,
    end: number,
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
    disposition: Disposition = "confirmed",
  ): Detection {
    return {
      ...partial,
      source,
      context: this.extractContext(text, partial.start, partial.end),
      disposition,
    };
  }

  /**
   * Apply redactions / synthesizations to text. Returns the modified
   * text plus a per-detection RedactionEntry record.
   *
   * Detections are processed in **reverse order by start offset** so
   * that replacements don't shift the offsets of pending detections.
   * The redaction map is returned in **document order** (same order as
   * `detections`).
   */
  protected async applyRedactions(
    text: string,
    detections: Detection[],
    mode: GuardMode,
    redactCtx?: RedactContext,
  ): Promise<{ text: string; redactionMap: RedactionEntry[] }> {
    const consistencyMap = redactCtx?.consistencyMap ?? new Map<string, string>();
    const registry = redactCtx?.registry;

    // Compute per-detection replacements. Order matters for synthesize
    // mode (consistency map writes happen as we go), so we walk in
    // document order to fill the map, then apply in reverse for slicing.
    const redactionMap: RedactionEntry[] = [];
    for (const detection of detections) {
      const replacement = await planReplacement(detection, mode, { registry, consistencyMap });
      redactionMap.push(replacement);
      // Cache for any subsequent detection of the same original within this call.
      consistencyMap.set(detection.text, replacement.replacement);
    }

    // Apply in reverse order by start position.
    const indexed = detections.map((d, i) => ({ d, entry: redactionMap[i] }));
    const sorted = indexed.sort((a, b) => b.d.start - a.d.start);
    let result = text;
    for (const { d, entry } of sorted) {
      result = result.slice(0, d.start) + entry.replacement + result.slice(d.end);
    }
    return { text: result, redactionMap };
  }

}
