/**
 * US-specific PII patterns.
 * Ported from Microsoft Presidio. See ATTRIBUTION.md.
 */

import type { PiiPattern } from "../../types";
import {
  validateSsn,
  luhn,
  npiLuhn,
  abaRouting,
  deaChecksum,
} from "../../validators/checksums";

export const US_SSN: PiiPattern = {
  entityType: "US_SSN",
  patterns: [
    // SSN with delimiters (medium confidence)
    /\b(\d{3})[- .](\d{2})[- .](\d{4})\b/g,
    // SSN without delimiters (very weak — needs context)
    /\b\d{9}\b/g,
  ],
  validate: validateSsn,
  contextWords: ["social", "security", "ssn", "ssns", "ssid"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const US_DRIVER_LICENSE: PiiPattern = {
  entityType: "US_DRIVER_LICENSE",
  patterns: [
    // State-specific alphanumeric formats
    /\b(?:[A-Z]\d{3,6}|[A-Z]\d{5,9}|[A-Z]\d{6,8}|[A-Z]\d{4,8}|[A-Z]\d{9,11}|[A-Z]{1,2}\d{5,6}|H\d{8}|V\d{6}|X\d{8}|[A-Z]{2}\d{2,5}|[A-Z]{2}\d{3,7}|\d{2}[A-Z]{3}\d{5,6}|[A-Z]\d{13,14}|[A-Z]\d{18}|[A-Z]\d{6}R|[A-Z]\d{9}|[A-Z]\d{1,12}|\d{9}[A-Z]|[A-Z]{2}\d{6}[A-Z]|\d{8}[A-Z]{2}|\d{3}[A-Z]{2}\d{4}|[A-Z]\d[A-Z]\d[A-Z]|\d{7,8}[A-Z])\b/g,
  ],
  contextWords: [
    "driver",
    "license",
    "permit",
    "lic",
    "identification",
    "dls",
    "cdls",
    "driving",
  ],
  baseConfidence: "low",
  baseScore: 0.3,
};

export const US_PASSPORT: PiiPattern = {
  entityType: "US_PASSPORT",
  patterns: [
    // Next generation passport (letter + 8 digits)
    /\b[A-Z]\d{8}\b/g,
    // Standard passport (9 digits)
    /\b\d{9}\b/g,
  ],
  contextWords: [
    "us",
    "united",
    "states",
    "passport",
    "travel",
    "document",
  ],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const US_BANK_NUMBER: PiiPattern = {
  entityType: "US_BANK_NUMBER",
  patterns: [/\b\d{8,17}\b/g],
  contextWords: [
    "check",
    "account",
    "acct",
    "bank",
    "save",
    "debit",
    "routing",
  ],
  baseConfidence: "low",
  baseScore: 0.05,
};

export const US_ITIN: PiiPattern = {
  entityType: "US_ITIN",
  patterns: [
    // With delimiters (medium)
    /\b9\d{2}[- ](5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])[- ]\d{4}\b/g,
    // Without delimiters (weak)
    /\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])\d{4}\b/g,
  ],
  contextWords: [
    "individual",
    "taxpayer",
    "itin",
    "tax",
    "payer",
    "taxid",
    "tin",
  ],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const US_MBI: PiiPattern = {
  entityType: "US_MBI",
  patterns: (() => {
    // MBI format: C A AN N A AN N A A N N
    // Valid letters: A-Z excluding S, L, O, I, B, Z
    const A = "[ACDEFGHJKMNPQRTUVWXY]";
    const AN = "[0-9ACDEFGHJKMNPQRTUVWXY]";
    const N = "[0-9]";
    const base = `${N}${A}${AN}${N}${A}${AN}${N}${A}${A}${N}${N}`;
    const withDash = `${N}${A}${AN}${N}-${A}${AN}${N}-${A}${A}${N}${N}`;
    return [new RegExp(`\\b${base}\\b`, "g"), new RegExp(`\\b${withDash}\\b`, "g")];
  })(),
  contextWords: [
    "medicare",
    "mbi",
    "beneficiary",
    "cms",
    "medicaid",
    "hic",
    "hicn",
  ],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const US_NPI: PiiPattern = {
  entityType: "US_NPI",
  patterns: [
    // With delimiters
    /\b[12]\d{3}[ -]\d{3}[ -]\d{3}\b/g,
    // Without delimiters
    /\b[12]\d{9}\b/g,
  ],
  validate: (match) => {
    const digits = match.replace(/\D/g, "");
    // Reject all same digits
    if (digits.length > 1 && new Set(digits.slice(0, -1)).size === 1) return false;
    return npiLuhn(match);
  },
  contextWords: [
    "npi",
    "national provider",
    "provider",
    "provider id",
    "provider identifier",
    "taxonomy",
  ],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const ABA_ROUTING_NUMBER: PiiPattern = {
  entityType: "ABA_ROUTING_NUMBER",
  patterns: [
    // With dashes
    /\b[0123678]\d{3}-\d{4}-\d\b/g,
    // Without dashes
    /\b[0123678]\d{8}\b/g,
  ],
  validate: abaRouting,
  contextWords: [
    "aba",
    "routing",
    "abarouting",
    "association",
    "bankrouting",
  ],
  baseConfidence: "low",
  baseScore: 0.05,
};

export const MEDICAL_LICENSE: PiiPattern = {
  entityType: "MEDICAL_LICENSE",
  patterns: [
    /[abcdefghjklmprstuxABCDEFGHJKLMPRSTUX][a-zA-Z]\d{7}/g,
    /[abcdefghjklmprstuxABCDEFGHJKLMPRSTUX]9\d{7}/g,
  ],
  validate: deaChecksum,
  contextWords: ["medical", "certificate", "DEA", "dea"],
  baseConfidence: "low",
  baseScore: 0.4,
};

/** All US-specific PII patterns */
export const US_PATTERNS: PiiPattern[] = [
  US_SSN,
  US_DRIVER_LICENSE,
  US_PASSPORT,
  US_BANK_NUMBER,
  US_ITIN,
  US_MBI,
  US_NPI,
  ABA_ROUTING_NUMBER,
  MEDICAL_LICENSE,
];
