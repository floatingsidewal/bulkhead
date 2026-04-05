/**
 * Injection Guard — detects prompt injection attempts.
 * Detection approach inspired by HAI-Guardrails. See ATTRIBUTION.md.
 */

import { BaseGuard } from "./base.guard";
import type { GuardConfig, GuardResult, Detection } from "../types";
import { INJECTION_PATTERNS, INJECTION_KEYWORDS } from "../patterns/injection";
import { findBestMatch } from "string-similarity";

const HEURISTIC_THRESHOLD = 0.7;

export class InjectionGuard extends BaseGuard {
  readonly name = "injection";

  async analyze(
    text: string,
    config?: Partial<GuardConfig>
  ): Promise<GuardResult> {
    const cfg = this.mergeConfig({ threshold: 0.6, mode: "block", ...config });
    const detections: Detection[] = [];

    // Tactic 1: Pattern matching
    for (const pattern of INJECTION_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags + "g");
      let match: RegExpExecArray | null;
      while ((match = re.exec(text)) !== null) {
        detections.push(
          this.makeDetection(text, {
            entityType: "PROMPT_INJECTION",
            start: match.index,
            end: match.index + match[0].length,
            text: match[0],
            confidence: "high",
            score: 0.9,
            guardName: this.name,
          })
        );
      }
    }

    // Tactic 2: Heuristic (string similarity against known phrases)
    if (detections.length === 0) {
      const score = this.heuristicScore(text);
      if (score >= cfg.threshold) {
        detections.push(
          this.makeDetection(text, {
            entityType: "PROMPT_INJECTION",
            start: 0,
            end: text.length,
            text: text.slice(0, 200),
            confidence: score >= 0.8 ? "high" : "medium",
            score,
            guardName: this.name,
          })
        );
      }
    }

    return this.buildResult(text, detections, cfg.mode);
  }

  private heuristicScore(text: string): number {
    const normalized = text.toLowerCase().trim();
    if (normalized.length === 0 || INJECTION_KEYWORDS.length === 0) return 0;

    // Check full text similarity against keywords
    const result = findBestMatch(normalized, INJECTION_KEYWORDS);
    let bestScore = result.bestMatch.rating;

    // Also check sliding windows for longer texts
    if (normalized.length > 100) {
      const windowSize = 80;
      const step = 30;
      for (let i = 0; i <= normalized.length - windowSize; i += step) {
        const window = normalized.slice(i, i + windowSize);
        const windowResult = findBestMatch(window, INJECTION_KEYWORDS);
        bestScore = Math.max(bestScore, windowResult.bestMatch.rating);
      }
    }

    return bestScore;
  }
}
