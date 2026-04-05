import type { Guard, GuardResult, EngineConfig, GuardConfig } from "../types";
import {
  CascadeClassifier,
  type CascadeConfig,
} from "../cascade/cascade";

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

  /** Clean up resources (terminate BERT worker, etc.) */
  async dispose(): Promise<void> {
    if (this.cascade) {
      await this.cascade.dispose();
      this.cascade = null;
    }
  }
}
