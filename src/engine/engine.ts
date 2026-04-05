import type { Guard, GuardResult, EngineConfig, GuardConfig } from "../types";

/** Orchestrates multiple guards and aggregates results */
export class GuardrailsEngine {
  private guards: Guard[] = [];
  private config: EngineConfig;

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

  /** Update engine configuration */
  updateConfig(config: Partial<EngineConfig>): void {
    this.config = { ...this.config, ...config };
    if (config.guards) {
      this.config.guards = { ...this.config.guards, ...config.guards };
    }
  }
}
