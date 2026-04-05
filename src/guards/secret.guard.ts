/**
 * Secret Guard — detects API keys, tokens, credentials, and connection strings.
 * Pattern approach inspired by HAI-Guardrails. See ATTRIBUTION.md.
 */

import { BaseGuard } from "./base.guard";
import type { GuardConfig, GuardResult, Detection } from "../types";
import { ALL_SECRET_PATTERNS } from "../patterns/secrets";
import { shannonEntropy } from "../validators/checksums";

export class SecretGuard extends BaseGuard {
  readonly name = "secret";

  async analyze(
    text: string,
    config?: Partial<GuardConfig>
  ): Promise<GuardResult> {
    const cfg = this.mergeConfig(config);
    const detections: Detection[] = [];

    for (const pattern of ALL_SECRET_PATTERNS) {
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

          detections.push({
            entityType: pattern.secretType,
            start,
            end,
            text: fullMatch,
            confidence: "high",
            score: 0.9,
            guardName: this.name,
          });
        }
      }
    }

    return this.buildResult(text, detections, cfg.mode);
  }
}
