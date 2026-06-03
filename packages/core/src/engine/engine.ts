import type {
  Guard,
  GuardResult,
  EngineConfig,
  GuardConfig,
  Detection,
  RedactContext,
  RedactionEntry,
  Synthesizer,
  ObjectScanResult,
} from "../types";
import {
  CascadeClassifier,
  type CascadeConfig,
} from "../cascade/cascade";
import type { PolicyDefinition, RiskAssessment, TemporalPolicy } from "../policy/types";
import { assessRisk } from "../policy/risk";
import { computeTemporalReplacements } from "../policy/temporal";
import { SynthesizerRegistry } from "../synthesizers/registry";

/** Orchestrates multiple guards and aggregates results */
export class GuardrailsEngine {
  private guards: Guard[] = [];
  private config: EngineConfig;
  private cascade: CascadeClassifier | null = null;
  private synthRegistry: SynthesizerRegistry;
  private temporalPolicy: TemporalPolicy | undefined;
  private _excludeEntities: Set<string> = new Set();

  constructor(config?: Partial<EngineConfig>) {
    this.config = {
      guards: {},
      ...config,
    };
    this.synthRegistry = new SynthesizerRegistry();
  }

  /**
   * Replace or extend the synthesizer registry. Registered synthesizers
   * override defaults for the same entity type. Returns this for chaining.
   *
   * Synthesizers are looked up at scan time when a guard runs in
   * `mode: "synthesize"`. See ./synthesizers/defaults.ts for the built-in
   * set.
   */
  setSynthesizers(synths: Record<string, Synthesizer>): this {
    this.synthRegistry.setMany(synths);
    return this;
  }

  /** Access the active synthesizer registry (defaults + user-registered). */
  get synthesizers(): SynthesizerRegistry {
    return this.synthRegistry;
  }

  /**
   * Set the temporal policy applied to detected timestamps. Default is
   * undefined (equivalent to `{ mode: "preserve" }` — no transformation).
   *
   * When set, every `engine.scan()` call applies the policy: detected
   * `DATE_TIME` entities are rebased per the policy mode and the rebased
   * values flow through the redaction pipeline via the per-call
   * consistency map. Composes with synthesize mode (a date that's both
   * rebased AND meant to be synthesized: temporal wins because it
   * pre-populates the cache before guards run).
   */
  setTemporalPolicy(policy: TemporalPolicy | undefined): this {
    this.temporalPolicy = policy;
    return this;
  }

  /** Read the active temporal policy, if any. */
  get temporalPolicyConfig(): TemporalPolicy | undefined {
    return this.temporalPolicy;
  }

  /**
   * Set entity types to exclude from remediation. Excluded entities are
   * still detected and reported in results, but their original text is
   * preserved (not redacted or synthesized). Detections for excluded
   * entities are omitted from the aggregate redactionMap.
   */
  setExcludeEntities(entityTypes: string[]): this {
    this._excludeEntities = new Set(entityTypes);
    return this;
  }

  /** Read the set of excluded entity types. */
  get excludeEntities(): ReadonlySet<string> {
    return this._excludeEntities;
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

  /**
   * Run all enabled guards against the input text.
   *
   * When `redactCtx` is omitted the engine creates a default context
   * (engine registry + fresh consistency map) so that direct callers
   * and the regex-only fallback paths inside `deepScan()`/`modelScan()`
   * all receive the synthesizer registry. This ensures `mode:
   * "synthesize"` works correctly across every engine entry point, not
   * only when called from `scan()`.
   */
  async analyze(text: string, redactCtx?: RedactContext): Promise<GuardResult[]> {
    const ctx: RedactContext = redactCtx ?? {
      registry: this.synthRegistry,
      consistencyMap: new Map<string, string>(),
    };
    const results: GuardResult[] = [];

    for (const guard of this.guards) {
      const guardConfig = this.getGuardConfig(guard.name);

      // Skip disabled guards
      if (guardConfig?.enabled === false) {
        continue;
      }

      const result = await guard.analyze(text, guardConfig, ctx);
      results.push(result);
    }

    return results;
  }

  /**
   * Run all guards and return a single pass/fail with all detections.
   *
   * When any guard runs in `mode: "redact"` or `mode: "synthesize"`,
   * the engine creates a per-call shared `consistencyMap` and passes
   * its synthesizer registry to every guard. This guarantees that the
   * same original value across detections from different guards
   * collapses to the same replacement (true cross-guard consistency
   * rather than the pre-Phase-6 behavior where the last guard's
   * `redactedText` won and earlier guards' redactions were lost).
   *
   * The aggregate `redactedText` reflects all guards' redactions in a
   * single output. The aggregate `redactionMap` is ordered by each
   * entry's `start` offset (document order), rather than by
   * guard-iteration order.
   */
  async scan(
    text: string,
    redactCtx?: RedactContext,
  ): Promise<{
    passed: boolean;
    results: GuardResult[];
    redactedText?: string;
    redactionMap?: RedactionEntry[];
  }> {
    const ctx: RedactContext = redactCtx ?? {
      registry: this.synthRegistry,
      consistencyMap: new Map<string, string>(),
    };

    // Temporal policy pre-pass: if a temporal policy is active, run a
    // cheap detection-only pass to find DATE_TIME entities, compute
    // their rebased forms, and seed the consistency map with them.
    // When the real analyze() pass runs, the cached values are picked
    // up by computeReplacement and used as redactions. Composes
    // cleanly with synthesize mode (cache write here happens before
    // any synthesizer is consulted, so temporal wins for dates).
    if (this.temporalPolicy && this.temporalPolicy.mode !== "preserve") {
      const detectionOnly = await this.analyze(text);
      const allDetections: Detection[] = [];
      for (const r of detectionOnly) {
        allDetections.push(...r.detections);
      }
      const temporalMap = computeTemporalReplacements(allDetections, this.temporalPolicy);
      for (const [original, rebased] of temporalMap) {
        ctx.consistencyMap!.set(original, rebased);
      }
    }

    const results = await this.analyze(text, ctx);
    const passed = results.every((r) => r.passed);

    // Entity exclusion: if excludeEntities is configured, detections
    // matching excluded entity types are preserved in results for
    // visibility but NOT applied as redactions. This implements
    // "detect-but-don't-act" semantics.
    const hasExclusions = this._excludeEntities.size > 0;

    // Aggregate redactedText across guards. Strategy: collect ALL
    // detections from ALL guards into a single list, then perform one
    // unified redaction pass against the original text using the same
    // consistency map. This avoids the prior bug where per-guard
    // redactions clobbered each other.
    let redactedText: string | undefined;
    const aggregateMap: RedactionEntry[] = [];
    const allRedactingGuards = results.filter(
      (r) => r.redactedText !== undefined && r.redactionMap !== undefined,
    );

    if (allRedactingGuards.length === 1 && !hasExclusions) {
      // Single redacting guard, no exclusions: trust its output verbatim.
      redactedText = allRedactingGuards[0].redactedText;
      aggregateMap.push(...allRedactingGuards[0].redactionMap!);
    } else if (allRedactingGuards.length >= 1) {
      // Multiple guards redacted, or exclusions are active: gather all
      // detections, filter excluded entities, sort by start descending,
      // apply replacements once. The consistency map is already shared
      // so synthesizers produce stable values.
      const allDetections: Array<{ d: Detection; entry: RedactionEntry }> = [];
      for (const r of allRedactingGuards) {
        const map = r.redactionMap!;
        for (let i = 0; i < r.detections.length; i++) {
          allDetections.push({ d: r.detections[i], entry: map[i] });
        }
      }

      // Filter out excluded entity types from redaction
      const activeDetections = hasExclusions
        ? allDetections.filter(({ entry }) => !this._excludeEntities.has(entry.entityType))
        : allDetections;

      if (activeDetections.length > 0) {
        // Apply in reverse start order; collect output entries in
        // document order for the aggregate map.
        const sorted = [...activeDetections].sort((a, b) => b.d.start - a.d.start);
        let result = text;
        for (const { d, entry } of sorted) {
          result = result.slice(0, d.start) + entry.replacement + result.slice(d.end);
        }
        redactedText = result;
        const docOrder = [...activeDetections].sort((a, b) => a.d.start - b.d.start);
        for (const { entry } of docOrder) {
          aggregateMap.push(entry);
        }
      } else {
        // All detections were excluded — no redaction needed
        redactedText = text;
      }
    }

    return {
      passed,
      results,
      redactedText,
      redactionMap: aggregateMap.length > 0 ? aggregateMap : undefined,
    };
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
    policy: PolicyDefinition,
  ): Promise<{
    passed: boolean;
    risk: RiskAssessment;
    results: GuardResult[];
    redactedText?: string;
    redactionMap?: RedactionEntry[];
  }> {
    const { passed, results, redactedText, redactionMap } = await this.scan(text);
    const risk = assessRisk(results, policy);
    return { passed, risk, results, redactedText, redactionMap };
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
   * Cross-leaf consistency: a single `consistencyMap` is created for
   * the entire `scanObject` call and threaded through every leaf scan.
   * In `mode: "synthesize"` (RFC-001), the same original value
   * produces the same synthetic replacement across all leaves of one
   * call.
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

    // Share one consistency map and registry across all leaf scans so
    // that the same original value produces the same synthetic
    // replacement everywhere in the document (cross-leaf consistency).
    const sharedCtx: RedactContext = {
      registry: this.synthRegistry,
      consistencyMap: new Map<string, string>(),
    };

    const walk = async (value: unknown, path: string): Promise<unknown> => {
      // Non-string primitives, null, undefined: pass through.
      if (value === null || value === undefined) return value;
      const t = typeof value;
      if (t === "number" || t === "boolean" || t === "bigint" || t === "symbol" || t === "function") {
        return value;
      }

      // String leaf: scan it using the shared context.
      if (t === "string") {
        const { passed, results, redactedText } = await this.scan(value as string, sharedCtx);
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
