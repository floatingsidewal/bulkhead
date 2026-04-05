/**
 * PII Guard — detects personally identifiable information using regex patterns.
 * Pattern library ported from Microsoft Presidio. See ATTRIBUTION.md.
 */

import { BaseGuard } from "./base.guard";
import type { GuardConfig, GuardResult, Detection, PiiPattern } from "../types";
import { ALL_PII_PATTERNS } from "../patterns/pii";

const CONTEXT_WINDOW = 100; // characters before/after match to search for context words
const CONTEXT_SCORE_BOOST = 0.35;

export interface PiiGuardOptions {
  /** Specific entity types to detect. If empty, all are enabled. */
  entityTypes?: string[];
  /** Additional custom patterns */
  customPatterns?: PiiPattern[];
}

export class PiiGuard extends BaseGuard {
  readonly name = "pii";
  private patterns: PiiPattern[];

  constructor(options?: PiiGuardOptions) {
    super();

    let patterns = ALL_PII_PATTERNS;
    if (options?.entityTypes && options.entityTypes.length > 0) {
      const allowed = new Set(options.entityTypes);
      patterns = patterns.filter((p) => allowed.has(p.entityType));
    }
    if (options?.customPatterns) {
      patterns = [...patterns, ...options.customPatterns];
    }
    this.patterns = patterns;
  }

  async analyze(
    text: string,
    config?: Partial<GuardConfig>
  ): Promise<GuardResult> {
    const cfg = this.mergeConfig(config);
    const detections = this.detectAll(text, cfg.threshold);
    return this.buildResult(text, detections, cfg.mode);
  }

  private detectAll(text: string, threshold: number): Detection[] {
    const allDetections: Detection[] = [];
    const textLower = text.toLowerCase();

    for (const pattern of this.patterns) {
      for (const regex of pattern.patterns) {
        // Reset regex state for global patterns
        const re = new RegExp(regex.source, regex.flags);
        let match: RegExpExecArray | null;

        while ((match = re.exec(text)) !== null) {
          const matchText = match[0];
          const start = match.index;
          const end = start + matchText.length;

          // Run validation if available
          if (pattern.validate && !pattern.validate(matchText)) {
            continue;
          }

          // Calculate score with context boost
          let score = pattern.baseScore;
          let confidence = pattern.baseConfidence;

          if (pattern.contextWords && pattern.contextWords.length > 0) {
            const contextStart = Math.max(0, start - CONTEXT_WINDOW);
            const contextEnd = Math.min(text.length, end + CONTEXT_WINDOW);
            const context = textLower.slice(contextStart, contextEnd);

            const hasContext = pattern.contextWords.some((word) =>
              context.includes(word.toLowerCase())
            );

            if (hasContext) {
              score = Math.min(1, score + CONTEXT_SCORE_BOOST);
              if (confidence === "low") confidence = "medium";
              else if (confidence === "medium") confidence = "high";
            }
          }

          if (score < threshold) continue;

          allDetections.push(
            this.makeDetection(text, {
              entityType: pattern.entityType,
              start,
              end,
              text: matchText,
              confidence,
              score,
              guardName: this.name,
            })
          );
        }
      }
    }

    // Remove overlapping detections (keep highest score)
    return this.deduplicateDetections(allDetections);
  }

  private deduplicateDetections(detections: Detection[]): Detection[] {
    if (detections.length <= 1) return detections;

    // Sort by score descending
    const sorted = [...detections].sort((a, b) => b.score - a.score);
    const result: Detection[] = [];

    for (const detection of sorted) {
      const overlaps = result.some(
        (existing) =>
          detection.start < existing.end && detection.end > existing.start
      );
      if (!overlaps) {
        result.push(detection);
      }
    }

    // Sort by position for consistent output
    return result.sort((a, b) => a.start - b.start);
  }
}
