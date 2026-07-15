/**
 * Injection Guard — detects prompt injection attempts.
 * Detection approach inspired by HAI-Guardrails. See ATTRIBUTION.md.
 */

import { BaseGuard } from "./base.guard";
import type { GuardConfig, GuardResult, Detection, RedactContext } from "../types";
import { INJECTION_PATTERNS, INJECTION_KEYWORDS } from "../patterns/injection";
import { compareTwoStrings } from "string-similarity";

const HEURISTIC_WINDOW_SIZE = 80;
const HEURISTIC_WINDOW_STEP = 30;
const HEURISTIC_STOPWORDS = new Set([
  "a",
  "all",
  "an",
  "are",
  "as",
  "be",
  "for",
  "from",
  "if",
  "is",
  "me",
  "my",
  "no",
  "now",
  "of",
  "on",
  "the",
  "to",
  "were",
  "what",
  "will",
  "you",
  "your",
]);
const HEURISTIC_SIGNAL_TOKENS = new Set([
  "act",
  "admin",
  "bypass",
  "dan",
  "developer",
  "disable",
  "disregard",
  "do",
  "forget",
  "ignore",
  "jailbreak",
  "override",
  "pretend",
  "reveal",
  "show",
  "sudo",
  "unlock",
]);

interface NormalizedText {
  normalized: string;
  indexMap: number[];
}

interface HeuristicMatch {
  score: number;
  keyword: string;
  windowStart: number;
  windowEnd: number;
}

export class InjectionGuard extends BaseGuard {
  readonly name = "injection";

  async analyze(
    text: string,
    config?: Partial<GuardConfig>,
    redactCtx?: RedactContext
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
      const match = this.heuristicScore(text);
      if (match.score >= cfg.threshold) {
        const matchedText = text.slice(match.windowStart, match.windowEnd);
        detections.push(
          this.makeDetection(text, {
            entityType: "PROMPT_INJECTION",
            start: match.windowStart,
            end: match.windowEnd,
            text: matchedText,
            confidence: match.score >= 0.8 ? "high" : "medium",
            score: match.score,
            guardName: this.name,
            matchedKeyword: match.keyword,
          })
        );
      }
    }

    return this.buildResult(text, detections, cfg.mode, redactCtx);
  }

  private heuristicScore(text: string): HeuristicMatch {
    const { normalized, indexMap } = this.normalizeForHeuristic(text);
    if (normalized.length === 0 || INJECTION_KEYWORDS.length === 0) {
      return { score: 0, keyword: "", windowStart: 0, windowEnd: 0 };
    }

    let bestMatch = this.scoreWindow(normalized, 0, normalized.length);
    if (normalized.length > 100) {
      for (
        let i = 0;
        i <= normalized.length - HEURISTIC_WINDOW_SIZE;
        i += HEURISTIC_WINDOW_STEP
      ) {
        const windowMatch = this.scoreWindow(
          normalized,
          i,
          i + HEURISTIC_WINDOW_SIZE,
        );
        if (windowMatch.score > bestMatch.score) {
          bestMatch = windowMatch;
        }
      }
    }

    if (bestMatch.score === 0) {
      return bestMatch;
    }

    return {
      ...bestMatch,
      windowStart: indexMap[bestMatch.windowStart],
      windowEnd: indexMap[bestMatch.windowEnd - 1] + 1,
    };
  }

  private normalizeForHeuristic(text: string): NormalizedText {
    let normalized = "";
    const indexMap: number[] = [];
    let pendingWhitespaceStart: number | null = null;
    let seenContent = false;

    for (let i = 0; i < text.length; i += 1) {
      const char = text[i];
      if (/\s/.test(char)) {
        if (seenContent && pendingWhitespaceStart === null) {
          pendingWhitespaceStart = i;
        }
        continue;
      }

      if (pendingWhitespaceStart !== null && normalized.length > 0) {
        normalized += " ";
        indexMap.push(pendingWhitespaceStart);
        pendingWhitespaceStart = null;
      }

      normalized += char.toLowerCase();
      indexMap.push(i);
      seenContent = true;
    }

    return { normalized, indexMap };
  }

  private scoreWindow(
    normalized: string,
    windowStart: number,
    windowEnd: number,
  ): HeuristicMatch {
    const window = normalized.slice(windowStart, windowEnd);
    let bestMatch: HeuristicMatch = {
      score: 0,
      keyword: "",
      windowStart,
      windowEnd,
    };

    for (const keyword of INJECTION_KEYWORDS) {
      const score = compareTwoStrings(window, keyword);
      if (score <= bestMatch.score) {
        continue;
      }

      if (!this.hasMeaningfulTokenOverlap(window, keyword)) {
        continue;
      }

      bestMatch = {
        score,
        keyword,
        windowStart,
        windowEnd,
      };
    }

    return bestMatch;
  }

  private hasMeaningfulTokenOverlap(window: string, keyword: string): boolean {
    const windowTokens = this.tokenize(window);
    const keywordTokens = this.tokenize(keyword);
    const sharedTokens = [...windowTokens].filter((token) => keywordTokens.has(token));

    if (sharedTokens.length >= 2) {
      return true;
    }

    return (
      sharedTokens.length === 1 &&
      keywordTokens.size === 1 &&
      HEURISTIC_SIGNAL_TOKENS.has(sharedTokens[0])
    );
  }

  private tokenize(value: string): Set<string> {
    const matches = value.match(/[a-z0-9]+/g) ?? [];
    return new Set(matches.filter((token) => !HEURISTIC_STOPWORDS.has(token)));
  }
}
