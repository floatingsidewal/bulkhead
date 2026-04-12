/**
 * Test Data Guard — detects synthetic, eval, and placeholder data.
 * This guard identifies data that was clearly fabricated for testing rather than
 * real sensitive content. Detections are informational, not blocking.
 */

import { BaseGuard } from "./base.guard";
import type { GuardConfig, GuardResult, Detection } from "../types";

/** Patterns for detecting synthetic/test data */
interface TestDataPattern {
  entityType: string;
  patterns: RegExp[];
  /** Human-readable reason for the flag */
  reason: string;
}

/**
 * GUIDs with embedded keywords (eval, test, demo, mock, fake, sample, example, placeholder)
 * or all-zero segments indicating fabricated identifiers.
 */
const SYNTHETIC_GUID_KEYWORDS =
  /\b[0-9a-f]{8}-(?:eval|test|demo|mock|fake|sample|exam|plac)[0-9a-f-]*\b/gi;

/**
 * GUIDs that are all zeros or have obvious zero-padding with a small counter.
 * e.g., 00000000-0000-0000-0000-000000000000, 00000000-eval-0005-0000-000000000001
 */
const ZERO_PADDED_GUID =
  /\b0{8}-[0-9a-f]{4}-[0-9a-f]{4}-0{4}-0{12}\b/gi;

/** Well-known test credit card numbers from Stripe, PayPal, Braintree docs */
const TEST_CREDIT_CARDS = [
  "4111111111111111", // Visa test
  "4242424242424242", // Stripe Visa
  "5500000000000004", // Mastercard test
  "5555555555554444", // Stripe Mastercard
  "378282246310005",  // Amex test
  "371449635398431",  // Amex test
  "6011111111111117", // Discover test
  "3056930009020004", // Diners test
  "3566002020360505", // JCB test
  "4000056655665556", // Stripe debit
];

/** Known invalid/reserved SSNs used in testing */
const TEST_SSNS = [
  "000-00-0000",
  "123-45-6789",
  "078-05-1120", // Woolworth wallet card SSN (famous invalid)
  "219-09-9999", // Social Security ad SSN
];

const TEST_DATA_PATTERNS: TestDataPattern[] = [
  {
    entityType: "TEST_DATA_GUID",
    patterns: [SYNTHETIC_GUID_KEYWORDS, ZERO_PADDED_GUID],
    reason: "synthetic-guid",
  },
  {
    entityType: "TEST_DATA_CREDIT_CARD",
    patterns: TEST_CREDIT_CARDS.map(
      (num) => new RegExp(`\\b${num}\\b`, "g")
    ),
    reason: "test-credit-card",
  },
  {
    entityType: "TEST_DATA_SSN",
    patterns: TEST_SSNS.map(
      // Require dashes or spaces between SSN groups (not embedded in other numbers)
      (ssn) => new RegExp(`\\b${ssn.replace(/-/g, "[\\s-]")}\\b`, "g")
    ),
    reason: "test-ssn",
  },
  {
    entityType: "TEST_DATA_EMAIL",
    patterns: [
      /\b[\w.+-]+@(?:example\.(?:com|org|net)|test\.com|mailinator\.com|tempmail\.com)\b/gi,
      /\bnoreply@[^\s]+\b/gi,
    ],
    reason: "placeholder-email",
  },
  {
    entityType: "TEST_DATA_PHONE",
    patterns: [
      /\b(?:\+?1[-.\s]?)?(?:\()?555[-.\s]?01[0-9]{2}(?:\))?[-.\s]?\d{4}\b/g, // 555-01xx range (reserved fictional)
    ],
    reason: "fictional-phone",
  },
  {
    entityType: "TEST_DATA_SEQUENTIAL",
    patterns: [
      /\b[A]{4,}0{6,}[0-9A-F]{1,4}\b/gi,    // AAAA000000000001 pattern
      /\b1234567890abcdef\b/gi,                // Classic sequential hex (exact)
    ],
    reason: "sequential-pattern",
  },
];

export class TestDataGuard extends BaseGuard {
  readonly name = "testdata";

  async analyze(
    text: string,
    config?: Partial<GuardConfig>
  ): Promise<GuardResult> {
    const cfg = this.mergeConfig(config);
    const detections: Detection[] = [];

    for (const pattern of TEST_DATA_PATTERNS) {
      for (const regex of pattern.patterns) {
        const re = new RegExp(regex.source, regex.flags);
        let match: RegExpExecArray | null;

        while ((match = re.exec(text)) !== null) {
          const matchText = match[0];
          const start = match.index;
          const end = start + matchText.length;

          detections.push(
            this.makeDetection(
              text,
              {
                entityType: pattern.entityType,
                start,
                end,
                text: matchText,
                confidence: "high",
                score: 0.95,
                guardName: this.name,
              },
              "regex",
              "informational"
            )
          );
        }
      }
    }

    // Deduplicate overlapping detections
    const deduped = this.deduplicateDetections(detections);
    return this.buildInformationalResult(text, deduped);
  }

  /** Build a result that always passes — test data is informational, not blocking */
  private buildInformationalResult(
    text: string,
    detections: Detection[]
  ): GuardResult {
    const score =
      detections.length > 0
        ? Math.max(...detections.map((d) => d.score))
        : 0;

    const types = [...new Set(detections.map((d) => d.entityType))];

    return {
      passed: true, // Always passes — informational only
      reason:
        detections.length === 0
          ? "No test data detected"
          : `Test data detected: ${types.join(", ")}`,
      guardName: this.name,
      score,
      detections,
    };
  }

  private deduplicateDetections(detections: Detection[]): Detection[] {
    if (detections.length <= 1) return detections;
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
    return result.sort((a, b) => a.start - b.start);
  }
}
