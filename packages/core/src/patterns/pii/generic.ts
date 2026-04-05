/**
 * Generic PII patterns — not country-specific.
 * Ported from Microsoft Presidio. See ATTRIBUTION.md.
 */

import type { PiiPattern } from "../../types";
import { luhn, ibanMod97, validateMac } from "../../validators/checksums";

export const CREDIT_CARD: PiiPattern = {
  entityType: "CREDIT_CARD",
  patterns: [
    /\b(?!1\d{12}(?!\d))((4\d{3})|(5[0-5]\d{2})|(6\d{3})|(1\d{3})|(3\d{3}))[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b/g,
  ],
  validate: (match) => luhn(match.replace(/[\s-]/g, "")),
  contextWords: [
    "credit",
    "card",
    "visa",
    "mastercard",
    "cc",
    "amex",
    "discover",
    "jcb",
    "diners",
    "maestro",
    "instapayment",
  ],
  baseConfidence: "medium",
  baseScore: 0.3,
};

export const EMAIL_ADDRESS: PiiPattern = {
  entityType: "EMAIL_ADDRESS",
  patterns: [
    /\b(?:[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~](?:[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~.]{0,62}[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~])?)@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b/g,
  ],
  contextWords: ["email", "e-mail", "mail"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const IBAN_CODE: PiiPattern = {
  entityType: "IBAN_CODE",
  patterns: [
    /(?<![A-Z0-9])([A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?)(?![A-Z0-9])/g,
  ],
  validate: (match) => ibanMod97(match),
  contextWords: ["iban", "bank", "transaction"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const IP_ADDRESS: PiiPattern = {
  entityType: "IP_ADDRESS",
  patterns: [
    // IPv4
    /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    // IPv6 (simplified — common formats)
    /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    /\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b/g,
    /\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g,
  ],
  contextWords: ["ip", "ipv4", "ipv6", "address"],
  baseConfidence: "medium",
  baseScore: 0.6,
};

export const MAC_ADDRESS: PiiPattern = {
  entityType: "MAC_ADDRESS",
  patterns: [
    // Colon or hyphen separated
    /\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b/g,
    // Cisco dot format
    /\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b/g,
  ],
  validate: validateMac,
  contextWords: [
    "mac",
    "mac address",
    "hardware address",
    "physical address",
    "ethernet",
  ],
  baseConfidence: "medium",
  baseScore: 0.6,
};

export const PHONE_NUMBER: PiiPattern = {
  entityType: "PHONE_NUMBER",
  patterns: [
    // International format
    /\b\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    // International with country code
    /\b\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{0,4}\b/g,
  ],
  contextWords: [
    "phone",
    "number",
    "telephone",
    "cell",
    "cellphone",
    "mobile",
    "call",
    "tel",
    "fax",
  ],
  baseConfidence: "low",
  baseScore: 0.4,
};

export const URL: PiiPattern = {
  entityType: "URL",
  patterns: [
    /\bhttps?:\/\/[^\s<>"']+/gi,
    /\bwww\.[^\s<>"']+/gi,
  ],
  contextWords: ["url", "website", "link", "href"],
  baseConfidence: "medium",
  baseScore: 0.6,
};

export const CRYPTO: PiiPattern = {
  entityType: "CRYPTO",
  patterns: [
    // Bitcoin addresses (P2PKH, P2SH, Bech32)
    /(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}/g,
  ],
  contextWords: ["wallet", "btc", "bitcoin", "crypto", "blockchain"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const DATE_TIME: PiiPattern = {
  entityType: "DATE_TIME",
  patterns: [
    // ISO 8601
    /\b\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:[+-][0-2]\d:[0-5]\d|Z)\b/g,
    // mm/dd/yyyy or dd/mm/yyyy
    /\b(?:[0-3]?\d[/.-][0-3]?\d[/.-](?:\d{4}|\d{2}))\b/g,
    // yyyy-mm-dd
    /\b\d{4}[/.-](?:0?[1-9]|1[0-2])[/.-](?:0?[1-9]|[12]\d|3[01])\b/g,
  ],
  contextWords: ["date", "birthday", "born", "dob"],
  baseConfidence: "low",
  baseScore: 0.3,
};

/** All generic PII patterns */
export const GENERIC_PATTERNS: PiiPattern[] = [
  CREDIT_CARD,
  EMAIL_ADDRESS,
  IBAN_CODE,
  IP_ADDRESS,
  MAC_ADDRESS,
  PHONE_NUMBER,
  URL,
  CRYPTO,
  DATE_TIME,
];
