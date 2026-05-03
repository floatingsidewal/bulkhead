import type { Guard, GuardResult, EngineConfig, GuardConfig, ObjectScanResult, Detection } from "../types";
import {
  CascadeClassifier,
  type CascadeConfig,
} from "../cascade/cascade";
import type { PolicyDefinition, RiskAssessment } from "../policy/types";
import { assessRisk } from "../policy/risk";

/** Orchestrates multiple guards and aggregates results */
export class GuardrailsEngine {
  private guards: Guard[] = [];
  private config: EngineConfig;
  private cascade: CascadeClassifier | null = null;

  constructor(config?: Partial<EngineConfig>) {
    this.config = {
      guards: {},
      ...config,
    };
  }

  /** Register a guard with the engine */
  addGuard(guard: Guard): this {
    this.guards.push(guard);
    return this;
  }

  /** Register multiple guards */
  addGuards(guards: Guard[]): this {
    for (const guard of guards) {
      this.addGuard(guard);
    }
    return this;
  }

  /** Get configuration for a specific guard */
  private getGuardConfig(guardName: string): Partial<GuardConfig> | undefined {
    return this.config.guards[guardName];
  }

  /** Run all enabled guards against the input text */
  async analyze(text: string): Promise<GuardResult[]> {
    const results: GuardResult[] = [];

    for (const guard of this.guards) {
      const guardConfig = this.getGuardConfig(guard.name);

      // Skip disabled guards
      if (guardConfig?.enabled === false) {
        continue;
      }

      const result = await guard.analyze(text, guardConfig);
      results.push(result);
    }

    return results;
  }

  /** Run all guards and return a single pass/fail with all detections */
  async scan(text: string): Promise<{
    passed: boolean;
    results: GuardResult[];
    redactedText?: string;
  }> {
    const results = await this.analyze(text);
    const passed = results.every((r) => r.passed);

    // Build redacted text by applying all redactions
    let redactedText: string | undefined;
    for (const result of results) {
      if (result.redactedText) {
        redactedText = result.redactedText;
      }
    }

    return { passed, results, redactedText };
  }

  /** Get list of registered guard names */
  get guardNames(): string[] {
    return this.guards.map((g) => g.name);
  }

  /** Whether the cascade is ready (BERT model loaded if enabled) */
  get cascadeReady(): boolean {
    if (!this.cascade) return true; // No cascade = regex only, always ready
    return this.cascade.ready;
  }

  /** Initialize or update the cascade classifier */
  initCascade(config?: Partial<CascadeConfig>): CascadeClassifier {
    this.cascade = new CascadeClassifier(config);
    for (const guard of this.guards) {
      this.cascade.addRegexGuard(guard);
    }
    return this.cascade;
  }

  /** Run the full cascade (regex + BERT + optional LLM) */
  async deepScan(text: string): Promise<GuardResult[]> {
    if (!this.cascade) {
      // Fall back to regex-only if cascade not initialized
      return this.analyze(text);
    }
    const cascadeResult = await this.cascade.deepScan(text);
    return [cascadeResult];
  }

  /** Run regex + BERT only (no LLM) */
  async modelScan(text: string): Promise<GuardResult[]> {
    if (!this.cascade) {
      return this.analyze(text);
    }
    const cascadeResult = await this.cascade.modelScan(text);
    return [cascadeResult];
  }

  /** Update engine configuration */
  updateConfig(config: Partial<EngineConfig>): void {
    this.config = { ...this.config, ...config };
    if (config.guards) {
      this.config.guards = { ...this.config.guards, ...config.guards };
    }
  }

  /** Run all guards and return risk assessment alongside results */
  async policyScan(
    text: string,
    policy: PolicyDefinition
  ): Promise<{
    passed: boolean;
    risk: RiskAssessment;
    results: GuardResult[];
    redactedText?: string;
  }> {
    const { passed, results, redactedText } = await this.scan(text);
    const risk = assessRisk(results, policy);
    return { passed, risk, results, redactedText };
  }

  /** Clean up resources (terminate BERT worker, etc.) */
  async dispose(): Promise<void> {
    if (this.cascade) {
      await this.cascade.dispose();
      this.cascade = null;
    }
  }

  /**
   * Run all enabled guards over every string leaf in a structured input
   * (object, array, or any combination) and return a result that
   * preserves the input's shape with string leaves redacted in place.
   *
   * Walking semantics:
   *   - Strings:   passed to `scan()`. Replaced with `redactedText` if
   *                guards produced redactions; otherwise pass-through.
   *   - Numbers, booleans, null, undefined, bigint, symbol, Date,
   *     RegExp, Map, Set, functions: pass through unchanged. Bulkhead
   *     does not classify non-string leaves.
   *   - Arrays:    each element walked with index appended to path.
   *   - Plain objects: each entry walked with key appended to path.
   *     Object key order is preserved.
   *
   * Cross-leaf consistency: each leaf is scanned independently. In
   * `mode: "redact"` this is irrelevant (all detections of the same
   * entity type produce the same `[REDACTED-TYPE]` placeholder). When
   * `mode: "synthesize"` ships (RFC-001), the consistency map will be
   * threaded through scanObject so the same original value produces
   * the same synthetic value across all leaves of one call.
   *
   * @param input  Any JSON-serializable structure, or a string. Generic
   *               type `T` is preserved on `redactedObject`.
   * @returns      ObjectScanResult with aggregated guard results,
   *               shape-preserving `redactedObject`, and per-path
   *               detection map.
   */
  async scanObject<T>(input: T): Promise<ObjectScanResult<T>> {
    const aggregateResults: GuardResult[] = [];
    const pathDetections: Record<string, Detection[]> = {};
    let allPassed = true;

    const walk = async (value: unknown, path: string): Promise<unknown> => {
      // Non-string primitives, null, undefined: pass through.
      if (value === null || value === undefined) return value;
      const t = typeof value;
      if (t === "number" || t === "boolean" || t === "bigint" || t === "symbol" || t === "function") {
        return value;
      }

      // String leaf: scan it.
      if (t === "string") {
        const { passed, results, redactedText } = await this.scan(value as string);
        if (!passed) allPassed = false;

        const leafDetections: Detection[] = [];
        for (const r of results) {
          if (r.detections.length === 0) continue;
          leafDetections.push(...r.detections);
          // Merge into aggregate per guardName
          let agg = aggregateResults.find((a) => a.guardName === r.guardName);
          if (!agg) {
            agg = {
              guardName: r.guardName,
              passed: true,
              reason: r.reason,
              score: 0,
              detections: [],
            };
            aggregateResults.push(agg);
          }
          agg.detections.push(...r.detections);
          agg.passed = agg.passed && r.passed;
          agg.score = Math.max(agg.score, r.score);
          if (!r.passed) agg.reason = r.reason;
        }
        if (leafDetections.length > 0) {
          pathDetections[path] = leafDetections;
        }
        return redactedText ?? value;
      }

      // Preserve well-known special objects without recursing.
      if (
        value instanceof Date ||
        value instanceof RegExp ||
        value instanceof Map ||
        value instanceof Set
      ) {
        return value;
      }

      // Array: recurse with [i] path segment.
      if (Array.isArray(value)) {
        const out: unknown[] = new Array(value.length);
        for (let i = 0; i < value.length; i++) {
          out[i] = await walk(value[i], `${path}[${i}]`);
        }
        return out;
      }

      // Plain object: recurse with .key path segment.
      if (t === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          const childPath = path ? `${path}.${k}` : k;
          out[k] = await walk(v, childPath);
        }
        return out;
      }

      // Unknown: pass through.
      return value;
    };

    const redactedObject = (await walk(input, "")) as T;

    return {
      passed: allPassed,
      results: aggregateResults,
      redactedObject,
      pathDetections,
    };
  }
}
