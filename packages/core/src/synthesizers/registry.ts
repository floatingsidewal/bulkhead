/**
 * SynthesizerRegistry — keyed by entity type, supplies replacement
 * functions used by `mode: "synthesize"`.
 *
 * The engine ships with default synthesizers for common PII types
 * (see ./defaults.ts). Consumers can override or extend them via
 * `engine.setSynthesizers({ EMAIL_ADDRESS: customFn, ... })`.
 *
 * Synthesizers are looked up by exact `entityType` match. A guard whose
 * detection has an entity type with no registered synthesizer falls back
 * to the standard `[REDACTED-TYPE]` placeholder (see base.guard.ts).
 */

import type { Synthesizer } from "../types";
import { DEFAULT_SYNTHESIZERS } from "./defaults";

export class SynthesizerRegistry {
  private map: Map<string, Synthesizer>;

  constructor(initial?: Record<string, Synthesizer>) {
    this.map = new Map();
    // Seed with built-in defaults; consumer overrides win on top.
    for (const [type, fn] of Object.entries(DEFAULT_SYNTHESIZERS)) {
      this.map.set(type, fn);
    }
    if (initial) {
      for (const [type, fn] of Object.entries(initial)) {
        this.map.set(type, fn);
      }
    }
  }

  /** Register / override a synthesizer for a specific entity type. */
  set(entityType: string, fn: Synthesizer): this {
    this.map.set(entityType, fn);
    return this;
  }

  /** Bulk-register synthesizers. Existing entries with the same entityType are overridden. */
  setMany(synths: Record<string, Synthesizer>): this {
    for (const [type, fn] of Object.entries(synths)) {
      this.map.set(type, fn);
    }
    return this;
  }

  /** Look up the synthesizer for an entity type, if any. */
  get(entityType: string): Synthesizer | undefined {
    return this.map.get(entityType);
  }

  /** Whether a synthesizer exists for this entity type (including defaults). */
  has(entityType: string): boolean {
    return this.map.has(entityType);
  }

  /** Remove a synthesizer (including any default for this type). */
  delete(entityType: string): boolean {
    return this.map.delete(entityType);
  }

  /** Iterate registered entity types. */
  entityTypes(): string[] {
    return [...this.map.keys()];
  }
}
