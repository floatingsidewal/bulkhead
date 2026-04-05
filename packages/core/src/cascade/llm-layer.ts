/**
 * LLM disambiguation layer (Layer 3) of the cascading classifier.
 * Only receives ambiguous spans from Layer 2, along with surrounding context.
 * Makes a focused determination: is this span PII or not?
 */

import type { Detection, Disposition } from "../types";

/** Function signature for an LLM provider */
export type LlmProvider = (prompt: string) => Promise<string>;

export interface LlmLayerConfig {
  /** Number of sentences before/after the span to include as context */
  contextSentences: number;
  /** LLM provider function */
  provider?: LlmProvider;
}

interface DisambiguationResult {
  type: string;
  confidence: number;
}

export class LlmLayer {
  private config: LlmLayerConfig;

  constructor(config?: Partial<LlmLayerConfig>) {
    this.config = {
      contextSentences: 3,
      ...config,
    };
  }

  /** Set the LLM provider (can be swapped at runtime) */
  setProvider(provider: LlmProvider): void {
    this.config.provider = provider;
  }

  /**
   * Disambiguate escalated detections using an LLM.
   * @param escalated Detections with disposition "escalate"
   * @param fullText The full document text
   * @param confirmed Already-confirmed detections (passed as context to help disambiguation)
   */
  async disambiguate(
    escalated: Detection[],
    fullText: string,
    confirmed: Detection[]
  ): Promise<Detection[]> {
    if (!this.config.provider) {
      // No LLM configured — return escalated items as-is
      return escalated;
    }

    const results: Detection[] = [];

    for (const detection of escalated) {
      const prompt = this.buildPrompt(detection, fullText, confirmed);

      try {
        const response = await this.config.provider(prompt);
        const parsed = this.parseResponse(response);

        if (parsed && parsed.type !== "NONE") {
          results.push({
            ...detection,
            entityType: parsed.type,
            score: parsed.confidence,
            confidence:
              parsed.confidence >= 0.9
                ? "high"
                : parsed.confidence >= 0.7
                  ? "medium"
                  : "low",
            source: "llm",
            disposition: "confirmed" as Disposition,
          });
        } else {
          results.push({
            ...detection,
            source: "llm",
            disposition: "dismissed" as Disposition,
          });
        }
      } catch {
        // LLM call failed — keep as escalated rather than losing data
        results.push(detection);
      }
    }

    return results;
  }

  /** Build a focused disambiguation prompt */
  private buildPrompt(
    detection: Detection,
    fullText: string,
    confirmed: Detection[]
  ): string {
    const contextWindow = this.extractSentenceContext(
      fullText,
      detection.start,
      detection.end
    );

    const confirmedList = confirmed
      .filter((d) => d.disposition === "confirmed")
      .map((d) => `${d.text} (${d.entityType})`)
      .slice(0, 10); // Limit to avoid excessive token use

    return `You are a PII detection system. Determine if the highlighted span is personally identifiable information.

Context: "${contextWindow}"
Span: "${detection.text}"
BERT suggested: ${detection.entityType} (confidence: ${detection.score.toFixed(2)})
${confirmedList.length > 0 ? `Other confirmed entities in document: [${confirmedList.join(", ")}]` : ""}

Is this span PII? If yes, what type? If it's ambiguous (e.g., "Jordan" could be a person or country), use the context to decide.

Respond with ONLY a JSON object: { "type": "PERSON"|"LOCATION"|"ORGANIZATION"|"NONE", "confidence": 0.0-1.0 }`;
  }

  /** Extract ±N sentences around a span */
  private extractSentenceContext(
    text: string,
    start: number,
    end: number
  ): string {
    const n = this.config.contextSentences;

    // Split into sentences (simple heuristic)
    const sentenceBreaks: number[] = [0];
    const sentenceRegex = /[.!?]+\s+/g;
    let match: RegExpExecArray | null;
    while ((match = sentenceRegex.exec(text)) !== null) {
      sentenceBreaks.push(match.index + match[0].length);
    }
    sentenceBreaks.push(text.length);

    // Find which sentence contains the span
    let spanSentenceIdx = 0;
    for (let i = 0; i < sentenceBreaks.length - 1; i++) {
      if (sentenceBreaks[i] <= start && start < sentenceBreaks[i + 1]) {
        spanSentenceIdx = i;
        break;
      }
    }

    // Extract ±n sentences
    const contextStart =
      sentenceBreaks[Math.max(0, spanSentenceIdx - n)];
    const contextEnd =
      sentenceBreaks[
        Math.min(sentenceBreaks.length - 1, spanSentenceIdx + n + 1)
      ];

    return text.slice(contextStart, contextEnd).trim();
  }

  /** Parse the LLM response JSON */
  private parseResponse(response: string): DisambiguationResult | null {
    try {
      // Extract JSON from response (may have surrounding text)
      const jsonMatch = response.match(/\{[^}]+\}/);
      if (!jsonMatch) return null;

      const parsed = JSON.parse(jsonMatch[0]);
      if (
        typeof parsed.type === "string" &&
        typeof parsed.confidence === "number"
      ) {
        return parsed as DisambiguationResult;
      }
      return null;
    } catch {
      return null;
    }
  }
}
