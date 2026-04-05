/**
 * Cascading Classifier — orchestrates the three detection layers.
 *
 * Layer 1 (Regex): Always runs, sub-ms. Catches structured PII.
 *   → confidence: 1.0, disposition: "confirmed"
 *
 * Layer 2 (BERT): On-demand, 20-50ms. Catches contextual entities.
 *   → score >= threshold: "confirmed"
 *   → score < threshold: "escalate"
 *
 * Layer 3 (LLM): Selective, 500ms-2s. Only sees escalated spans.
 *   → Returns "confirmed" or "dismissed"
 */

import type { Detection, GuardResult } from "../types";
import type { Guard } from "../types";
import { BertLayer, type BertLayerConfig } from "./bert-layer";
import { LlmLayer, type LlmProvider, type LlmLayerConfig } from "./llm-layer";

export interface CascadeConfig {
  /** Confidence threshold below which BERT results escalate to LLM */
  escalationThreshold: number;
  /** Number of sentences of context to pass to Layer 3 */
  contextSentences: number;
  /** Whether Layer 2 (BERT) is enabled */
  bertEnabled: boolean;
  /** Whether Layer 3 (LLM) is enabled */
  llmEnabled: boolean;
  /** Model ID for BERT layer */
  modelId?: string;
  /** LLM provider function for Layer 3 */
  llmProvider?: LlmProvider;
}

const DEFAULT_CASCADE_CONFIG: CascadeConfig = {
  escalationThreshold: 0.75,
  contextSentences: 3,
  bertEnabled: true,
  llmEnabled: false,
  modelId: "gravitee-io/bert-small-pii-detection",
};

export class CascadeClassifier {
  private config: CascadeConfig;
  private bertLayer: BertLayer | null = null;
  private llmLayer: LlmLayer;
  private regexGuards: Guard[] = [];

  constructor(config?: Partial<CascadeConfig>) {
    this.config = { ...DEFAULT_CASCADE_CONFIG, ...config };
    this.llmLayer = new LlmLayer({
      contextSentences: this.config.contextSentences,
      provider: this.config.llmProvider,
    });
  }

  /** Register regex-based guards (Layer 1) */
  addRegexGuard(guard: Guard): this {
    this.regexGuards.push(guard);
    return this;
  }

  /** Set the LLM provider for Layer 3 */
  setLlmProvider(provider: LlmProvider): void {
    this.config.llmProvider = provider;
    this.llmLayer.setProvider(provider);
  }

  /**
   * Run the full cascade: Regex → BERT → LLM
   * Returns a unified GuardResult with all detections carrying provenance.
   */
  async deepScan(text: string): Promise<GuardResult> {
    // === Layer 1: Regex (always) ===
    const regexDetections = await this.runRegexLayer(text);

    // If BERT is disabled, return regex-only results
    if (!this.config.bertEnabled) {
      return this.buildCascadeResult(text, regexDetections);
    }

    // === Layer 2: BERT ===
    const bertDetections = await this.runBertLayer(text);

    // Deduplicate: regex wins for overlapping spans
    const mergedBert = this.deduplicateAgainstRegex(
      bertDetections,
      regexDetections
    );

    const allDetections = [...regexDetections, ...mergedBert];

    // If LLM is disabled or no escalated items, return here
    const escalated = allDetections.filter((d) => d.disposition === "escalate");
    if (!this.config.llmEnabled || escalated.length === 0 || !this.config.llmProvider) {
      return this.buildCascadeResult(text, allDetections);
    }

    // === Layer 3: LLM (only escalated spans) ===
    const confirmed = allDetections.filter((d) => d.disposition === "confirmed");
    const resolved = await this.llmLayer.disambiguate(
      escalated,
      text,
      confirmed
    );

    // Replace escalated detections with resolved ones
    const finalDetections = [
      ...allDetections.filter((d) => d.disposition !== "escalate"),
      ...resolved,
    ];

    return this.buildCascadeResult(text, finalDetections);
  }

  /** Run Layer 1 only (for fast auto-scan path) */
  async regexScan(text: string): Promise<GuardResult> {
    const detections = await this.runRegexLayer(text);
    return this.buildCascadeResult(text, detections);
  }

  /** Run Layers 1 + 2 only (no LLM, for "Scan File" command) */
  async modelScan(text: string): Promise<GuardResult> {
    const regexDetections = await this.runRegexLayer(text);
    if (!this.config.bertEnabled) {
      return this.buildCascadeResult(text, regexDetections);
    }

    const bertDetections = await this.runBertLayer(text);
    const mergedBert = this.deduplicateAgainstRegex(
      bertDetections,
      regexDetections
    );

    return this.buildCascadeResult(text, [...regexDetections, ...mergedBert]);
  }

  // --- Private methods ---

  private async runRegexLayer(text: string): Promise<Detection[]> {
    const allDetections: Detection[] = [];
    for (const guard of this.regexGuards) {
      const result = await guard.analyze(text);
      allDetections.push(...result.detections);
    }
    return allDetections;
  }

  private async runBertLayer(text: string): Promise<Detection[]> {
    if (!this.bertLayer) {
      this.bertLayer = new BertLayer({
        modelId: this.config.modelId,
        escalationThreshold: this.config.escalationThreshold,
      });
    }
    return this.bertLayer.analyze(text);
  }

  /** Remove BERT detections that overlap with regex detections */
  private deduplicateAgainstRegex(
    bertDetections: Detection[],
    regexDetections: Detection[]
  ): Detection[] {
    return bertDetections.filter((bert) => {
      return !regexDetections.some(
        (regex) => bert.start < regex.end && bert.end > regex.start
      );
    });
  }

  private buildCascadeResult(
    text: string,
    detections: Detection[]
  ): GuardResult {
    // Only count non-dismissed detections as failures
    const activeDetections = detections.filter(
      (d) => d.disposition !== "dismissed"
    );
    const passed = activeDetections.length === 0;
    const score =
      activeDetections.length > 0
        ? Math.max(...activeDetections.map((d) => d.score))
        : 0;

    const sources = [...new Set(detections.map((d) => d.source))];
    const types = [...new Set(activeDetections.map((d) => d.entityType))];

    return {
      passed,
      reason: passed
        ? "No issues detected"
        : `Detected via ${sources.join("+")}: ${types.join(", ")}`,
      guardName: "cascade",
      score,
      detections,
    };
  }

  /** Clean up resources */
  async dispose(): Promise<void> {
    if (this.bertLayer) {
      await this.bertLayer.dispose();
      this.bertLayer = null;
    }
  }
}
