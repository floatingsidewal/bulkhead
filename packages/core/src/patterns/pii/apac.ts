/**
 * APAC + Africa PII patterns (SG, AU, IN, KR, TH, NG).
 * Ported from Microsoft Presidio. See ATTRIBUTION.md.
 */

import type { PiiPattern } from "../../types";
import { luhn } from "../../validators/checksums";
import { verhoeff } from "../../validators/verhoeff";

// --- Singapore ---

export const SG_NRIC_FIN: PiiPattern = {
  entityType: "SG_NRIC_FIN",
  patterns: [/\b[STFGM]\d{7}[A-Z]\b/gi],
  contextWords: ["fin", "nric"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const SG_UEN: PiiPattern = {
  entityType: "SG_UEN",
  patterns: [
    /\b\d{8}[A-Z]\b/g,
    /\b\d{9}[A-Z]\b/g,
    /\b[TS]\d{2}[A-Z]{2}\d{4}[A-Z]\b/g,
  ],
  contextWords: ["uen", "unique entity number", "business registration", "acra"],
  baseConfidence: "low",
  baseScore: 0.3,
};

// --- Australia ---

export const AU_ABN: PiiPattern = {
  entityType: "AU_ABN",
  patterns: [
    /\b\d{2}\s\d{3}\s\d{3}\s\d{3}\b/g,
    /\b\d{11}\b/g,
  ],
  validate: (match) => {
    const digits = match.replace(/\s/g, "").split("").map(Number);
    if (digits.length !== 11) return false;
    const weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    digits[0] = digits[0] === 0 ? 9 : digits[0] - 1;
    let sum = 0;
    for (let i = 0; i < 11; i++) {
      sum += digits[i] * weights[i];
    }
    return sum % 89 === 0;
  },
  contextWords: ["australian business number", "abn"],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const AU_ACN: PiiPattern = {
  entityType: "AU_ACN",
  patterns: [
    /\b\d{3}\s\d{3}\s\d{3}\b/g,
    /\b\d{9}\b/g,
  ],
  validate: (match) => {
    const digits = match.replace(/\s/g, "").split("").map(Number);
    if (digits.length !== 9) return false;
    const weights = [8, 7, 6, 5, 4, 3, 2, 1];
    let sum = 0;
    for (let i = 0; i < 8; i++) {
      sum += digits[i] * weights[i];
    }
    const complement = (10 - (sum % 10)) % 10;
    return complement === digits[8];
  },
  contextWords: ["australian company number", "acn"],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const AU_TFN: PiiPattern = {
  entityType: "AU_TFN",
  patterns: [
    /\b\d{3}\s\d{3}\s\d{3}\b/g,
    /\b\d{9}\b/g,
  ],
  validate: (match) => {
    const digits = match.replace(/\s/g, "").split("").map(Number);
    if (digits.length !== 9) return false;
    const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += digits[i] * weights[i];
    }
    return sum % 11 === 0;
  },
  contextWords: ["tax file number", "tfn"],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const AU_MEDICARE: PiiPattern = {
  entityType: "AU_MEDICARE",
  patterns: [
    /\b[2-6]\d{3}\s\d{5}\s\d\b/g,
    /\b[2-6]\d{9}\b/g,
  ],
  validate: (match) => {
    const digits = match.replace(/\s/g, "").split("").map(Number);
    if (digits.length !== 10) return false;
    const weights = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum = 0;
    for (let i = 0; i < 8; i++) {
      sum += digits[i] * weights[i];
    }
    return (sum % 10) === digits[8];
  },
  contextWords: ["medicare"],
  baseConfidence: "low",
  baseScore: 0.1,
};

// --- India ---

export const IN_PAN: PiiPattern = {
  entityType: "IN_PAN",
  patterns: [
    /\b[A-Z]{3}[ABCFGHHJLPT][A-Z]\d{4}[A-Z]\b/gi,
    /\b[A-Z]{5}\d{4}[A-Z]\b/gi,
  ],
  contextWords: ["permanent account number", "pan"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const IN_AADHAAR: PiiPattern = {
  entityType: "IN_AADHAAR",
  patterns: [
    /\b\d{4}[- :]\d{4}[- :]\d{4}\b/g,
    /\b\d{12}\b/g,
  ],
  validate: (match) => {
    const digits = match.replace(/\D/g, "");
    if (digits.length !== 12) return false;
    if (parseInt(digits[0], 10) < 2) return false;
    // Check palindrome
    if (digits === digits.split("").reverse().join("")) return false;
    return verhoeff(parseInt(digits, 10));
  },
  contextWords: ["aadhaar", "uidai"],
  baseConfidence: "low",
  baseScore: 0.01,
};

export const IN_VEHICLE_REGISTRATION: PiiPattern = {
  entityType: "IN_VEHICLE_REGISTRATION",
  patterns: [
    /\b[A-Z]{2}\d{2}[A-Z]{1,2}\d{4}\b/g,
    /\b[A-Z]{2}\d[A-Z]{1,3}\d{4}\b/g,
  ],
  contextWords: ["rto", "vehicle", "plate", "registration"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const IN_VOTER: PiiPattern = {
  entityType: "IN_VOTER",
  patterns: [
    /\b[A-Z]{3}\d{7}\b/gi,
  ],
  contextWords: ["voter", "epic", "elector photo identity card"],
  baseConfidence: "low",
  baseScore: 0.3,
};

export const IN_PASSPORT: PiiPattern = {
  entityType: "IN_PASSPORT",
  patterns: [/\b[A-Z][1-9]\d\s?\d{4}[1-9]\b/g],
  contextWords: ["passport", "indian passport", "passport number"],
  baseConfidence: "low",
  baseScore: 0.1,
};

// --- Korea ---

export const KR_RRN: PiiPattern = {
  entityType: "KR_RRN",
  patterns: [
    /(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?[1-4]\d{6}(?!\d)/g,
  ],
  validate: (match) => {
    const digits = match.replace(/-/g, "");
    if (digits.length !== 13 || !/^\d+$/.test(digits)) return false;
    const regionCode = parseInt(digits.slice(7, 9), 10);
    if (regionCode > 95) return false;
    const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum = 0;
    for (let i = 0; i < 12; i++) {
      sum += parseInt(digits[i], 10) * weights[i];
    }
    const checksum = (11 - (sum % 11)) % 10;
    return checksum === parseInt(digits[12], 10);
  },
  contextWords: [
    "resident registration number",
    "rrn",
    "korean rrn",
  ],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const KR_PASSPORT: PiiPattern = {
  entityType: "KR_PASSPORT",
  patterns: [
    /(?<![A-Z0-9])[MSROD]\d{3}[A-Z]\d{4}(?!\d)/gi,
    /(?<![A-Z0-9])[MSROD]\d{8}(?!\d)/gi,
  ],
  contextWords: ["passport", "korean passport", "여권"],
  baseConfidence: "low",
  baseScore: 0.1,
};

// --- Thailand ---

export const TH_TNIN: PiiPattern = {
  entityType: "TH_TNIN",
  patterns: [
    /\b[1-9](?:[134]\d|[25][0134567]|[67][01234567]|[89][0123456])\d{10}\b/g,
  ],
  validate: (match) => {
    if (match.length !== 13 || !/^\d+$/.test(match)) return false;
    const weights = [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum = 0;
    for (let i = 0; i < 12; i++) {
      sum += weights[i] * parseInt(match[i], 10);
    }
    const x = sum % 11;
    const expected = x <= 1 ? 1 - x : 11 - x;
    return expected === parseInt(match[12], 10);
  },
  contextWords: ["thai national id", "thai id number", "tnin"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

// --- Nigeria ---

export const NG_NIN: PiiPattern = {
  entityType: "NG_NIN",
  patterns: [/\b\d{11}\b/g],
  validate: (match) => {
    if (match.length !== 11 || !/^\d+$/.test(match)) return false;
    return verhoeff(parseInt(match, 10));
  },
  contextWords: [
    "nin",
    "national identification number",
    "national identity number",
    "nimc",
  ],
  baseConfidence: "low",
  baseScore: 0.01,
};

/** All APAC + Africa PII patterns */
export const APAC_PATTERNS: PiiPattern[] = [
  SG_NRIC_FIN,
  SG_UEN,
  AU_ABN,
  AU_ACN,
  AU_TFN,
  AU_MEDICARE,
  IN_PAN,
  IN_AADHAAR,
  IN_VEHICLE_REGISTRATION,
  IN_VOTER,
  IN_PASSPORT,
  KR_RRN,
  KR_PASSPORT,
  TH_TNIN,
  NG_NIN,
];
