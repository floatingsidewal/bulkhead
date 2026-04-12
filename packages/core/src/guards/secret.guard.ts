/**
 * Secret Guard — detects API keys, tokens, credentials, and connection strings.
 * Pattern approach inspired by HAI-Guardrails. See ATTRIBUTION.md.
 */

import { BaseGuard } from "./base.guard";
import type { GuardConfig, GuardResult, Detection, Confidence } from "../types";
import { ALL_SECRET_PATTERNS } from "../patterns/secrets/index";
import { shannonEntropy } from "../validators/checksums";

const CONTEXT_WINDOW = 100; // characters before/after match to search for context words
const CONTEXT_SCORE_BOOST = 0.35;

export interface SecretGuardOptions {
  /** Specific secret types to detect. If empty/undefined, all are enabled. */
  secretTypes?: string[];
}

export class SecretGuard extends BaseGuard {
  readonly name = "secret";
  private patterns: typeof ALL_SECRET_PATTERNS;

  constructor(options?: SecretGuardOptions) {
    super();
    let patterns = ALL_SECRET_PATTERNS;
    if (options?.secretTypes && options.secretTypes.length > 0) {
      const allowed = new Set(options.secretTypes);
      patterns = patterns.filter((p) => allowed.has(p.secretType));
    }
    this.patterns = patterns;
  }

  async analyze(
    text: string,
    config?: Partial<GuardConfig>
  ): Promise<GuardResult> {
    const cfg = this.mergeConfig(config);
    const detections: Detection[] = [];

    for (const pattern of this.patterns) {
      for (const regex of pattern.patterns) {
        const re = new RegExp(regex.source, regex.flags);
        let match: RegExpExecArray | null;

        while ((match = re.exec(text)) !== null) {
          const matchText = match[1] ?? match[0]; // Use capture group if present
          const fullMatch = match[0];
          const start = match.index;
          const end = start + fullMatch.length;

          // Validate against custom validator
          if (pattern.validate && !pattern.validate(matchText)) {
            continue;
          }

          // Entropy check for high-entropy patterns
          if (pattern.minEntropy) {
            const entropy = shannonEntropy(matchText);
            if (entropy < pattern.minEntropy) {
              continue;
            }
          }

          // Context-aware scoring: if pattern has contextWords, start at baseScore
          // and boost when context words are found nearby
          let score = pattern.baseScore ?? 0.9;
          let confidence: Confidence = pattern.baseConfidence ?? "high";

          if (pattern.contextWords && pattern.contextWords.length > 0) {
            const ctxStart = Math.max(0, start - CONTEXT_WINDOW);
            const ctxEnd = Math.min(text.length, end + CONTEXT_WINDOW);
            const context = text.slice(ctxStart, ctxEnd).toLowerCase();

            const hasContext = pattern.contextWords.some((word) =>
              context.includes(word.toLowerCase())
            );

            if (hasContext) {
              score = Math.min(1, score + CONTEXT_SCORE_BOOST);
              if (confidence === "low") confidence = "medium";
              else if (confidence === "medium") confidence = "high";
            }
          }

          if (score < cfg.threshold) continue;

          detections.push(
            this.makeDetection(text, {
              entityType: pattern.secretType,
              start,
              end,
              text: fullMatch,
              confidence,
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
