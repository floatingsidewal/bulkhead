/**
 * UK-specific PII patterns.
 * Ported from Microsoft Presidio. See ATTRIBUTION.md.
 */

import type { PiiPattern } from "../../types";

export const UK_NHS: PiiPattern = {
  entityType: "UK_NHS",
  patterns: [/\b(\d{3})[- ]?(\d{3})[- ]?(\d{4})\b/g],
  validate: (match) => {
    const digits = match.replace(/\D/g, "");
    if (digits.length !== 10) return false;
    let total = 0;
    for (let i = 0; i < 10; i++) {
      total += parseInt(digits[i], 10) * (10 - i);
    }
    return total % 11 === 0;
  },
  contextWords: [
    "national health service",
    "nhs",
    "health services authority",
    "health authority",
  ],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const UK_NINO: PiiPattern = {
  entityType: "UK_NINO",
  patterns: [
    /\b(?!BG|GB|NK|KN|NT|TN|ZZ)(?:[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z])\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
  ],
  contextWords: ["national insurance", "ni number", "nino"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const UK_PASSPORT: PiiPattern = {
  entityType: "UK_PASSPORT",
  patterns: [/\b[A-Z]{2}\d{7}\b/g],
  contextWords: [
    "passport",
    "passport number",
    "travel document",
    "uk passport",
    "british passport",
    "her majesty",
    "his majesty",
    "hm passport",
    "hmpo",
  ],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const UK_POSTCODE: PiiPattern = {
  entityType: "UK_POSTCODE",
  patterns: [
    /\b(?:GIR\s?0AA|[A-PR-UWYZ]\d[A-HJKPSTUW]?\s?\d[ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ]\d{2}\s?\d[ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HK-Y]\d[ABEHMNPRVWXY]?\s?\d[ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HK-Y]\d{2}\s?\d[ABD-HJLNP-UW-Z]{2})\b/g,
  ],
  contextWords: [
    "postcode",
    "post code",
    "postal code",
    "zip",
    "address",
    "delivery",
    "mailing",
    "shipping",
  ],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const UK_VEHICLE_REGISTRATION: PiiPattern = {
  entityType: "UK_VEHICLE_REGISTRATION",
  patterns: [
    // Current format
    /\b[A-HJ-PR-Y]{2}(?:0[1-9]|[1-7]\d)[- ]?[A-HJ-PR-Z]{3}\b/g,
    // Prefix format
    /\b[A-HJ-NPR-TV-Y]\d{1,3}[- ]?[A-HJ-PR-Y][A-HJ-PR-Z]{2}\b/g,
    // Suffix format
    /\b[A-HJ-PR-Z]{3}[- ]?\d{1,3}[- ]?[A-HJ-NPR-TV-Y]\b/g,
  ],
  contextWords: [
    "vehicle",
    "registration",
    "number plate",
    "licence plate",
    "license plate",
    "reg",
    "vrn",
    "dvla",
    "v5c",
    "mot",
    "car",
  ],
  baseConfidence: "low",
  baseScore: 0.2,
};

/** All UK-specific PII patterns */
export const UK_PATTERNS: PiiPattern[] = [
  UK_NHS,
  UK_NINO,
  UK_PASSPORT,
  UK_POSTCODE,
  UK_VEHICLE_REGISTRATION,
];
