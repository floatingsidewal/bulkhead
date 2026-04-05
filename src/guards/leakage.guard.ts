/**
 * Leakage Guard — detects system prompt extraction attempts.
 * Detection approach inspired by HAI-Guardrails. See ATTRIBUTION.md.
 */

import { BaseGuard } from "./base.guard";
import type { GuardConfig, GuardResult, Detection } from "../types";
import { LEAKAGE_PATTERNS, LEAKAGE_KEYWORDS } from "../patterns/injection";
import { findBestMatch } from "string-similarity";

export class LeakageGuard extends BaseGuard {
  readonly name = "leakage";

  async analyze(
    text: string,
    config?: Partial<GuardConfig>
  ): Promise<GuardResult> {
    const cfg = this.mergeConfig({ threshold: 0.6, mode: "block", ...config });
    const detections: Detection[] = [];

    // Tactic 1: Pattern matching
    for (const pattern of LEAKAGE_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags + "g");
      let match: RegExpExecArray | null;
      while ((match = re.exec(text)) !== null) {
        detections.push(
          this.makeDetection(text, {
            entityType: "PROMPT_LEAKAGE",
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

    // Tactic 2: Heuristic
    if (detections.length === 0) {
      const normalized = text.toLowerCase().trim();
      if (normalized.length > 0 && LEAKAGE_KEYWORDS.length > 0) {
        const result = findBestMatch(normalized, LEAKAGE_KEYWORDS);
        const score = result.bestMatch.rating;

        if (score >= cfg.threshold) {
          detections.push(
            this.makeDetection(text, {
              entityType: "PROMPT_LEAKAGE",
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
    }

    return this.buildResult(text, detections, cfg.mode);
  }
}
