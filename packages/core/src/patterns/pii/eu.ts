/**
 * EU-specific PII patterns (Spain, Italy, Poland, Finland, Sweden, Germany).
 * Ported from Microsoft Presidio. See ATTRIBUTION.md.
 */

import type { PiiPattern } from "../../types";

// --- Spain ---

export const ES_NIF: PiiPattern = {
  entityType: "ES_NIF",
  patterns: [/\b\d{7,8}[-]?[A-Z]\b/g],
  validate: (match) => {
    const cleaned = match.replace(/-/g, "");
    const letter = cleaned.slice(-1);
    const number = parseInt(cleaned.replace(/[^0-9]/g, ""), 10);
    const letters = "TRWAGMYFPDXBNJZSQVHLCKE";
    return letter === letters[number % 23];
  },
  contextWords: ["documento nacional de identidad", "dni", "nif", "identificación"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const ES_NIE: PiiPattern = {
  entityType: "ES_NIE",
  patterns: [/\b[XYZ]\d{7}[-]?[A-Z]\b/g],
  validate: (match) => {
    const cleaned = match.replace(/-/g, "");
    if (cleaned.length < 8 || cleaned.length > 9) return false;
    const letter = cleaned.slice(-1);
    const prefix = "XYZ".indexOf(cleaned[0]);
    if (prefix === -1) return false;
    const number = parseInt(prefix.toString() + cleaned.slice(1, -1), 10);
    const letters = "TRWAGMYFPDXBNJZSQVHLCKE";
    return letter === letters[number % 23];
  },
  contextWords: ["número de identificación de extranjero", "nie"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

// --- Italy ---

export const IT_FISCAL_CODE: PiiPattern = {
  entityType: "IT_FISCAL_CODE",
  patterns: [
    /(?:[A-Z][AEIOU][AEIOUX]|[AEIOU]X{2}|[B-DF-HJ-NP-TV-Z]{2}[A-Z]){2}(?:[\dLMNP-V]{2}(?:[A-EHLMPR-T](?:[04LQ][1-9MNP-V]|[15MR][\dLMNP-V]|[26NS][0-8LMNP-U])|[DHPS][37PT][0L]|[ACELMRT][37PT][01LM]|[AC-EHLMPR-T][26NS][9V])|(?:[02468LNQSU][048LQU]|[13579MPRTV][26NS])B[26NS][9V])(?:[A-MZ][1-9MNP-V][\dLMNP-V]{2}|[A-M][0L](?:[1-9MNP-V][\dLMNP-V]|[0L][1-9MNP-V]))[A-Z]/gi,
  ],
  validate: (match) => {
    const text = match.toUpperCase();
    if (text.length !== 16) return false;
    const control = text[15];
    const toValidate = text.slice(0, 15);

    const mapOdd: Record<string, number> = {
      "0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15, "7": 17,
      "8": 19, "9": 21, A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17,
      I: 19, J: 21, K: 2, L: 4, M: 18, N: 20, O: 11, P: 3, Q: 6, R: 8,
      S: 12, T: 14, U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23,
    };
    const mapEven: Record<string, number> = {
      "0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
      "8": 8, "9": 9, A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7,
      I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15, Q: 16, R: 17,
      S: 18, T: 19, U: 20, V: 21, W: 22, X: 23, Y: 24, Z: 25,
    };

    let oddSum = 0;
    let evenSum = 0;
    for (let i = 0; i < toValidate.length; i++) {
      if (i % 2 === 0) {
        oddSum += mapOdd[toValidate[i]] ?? 0;
      } else {
        evenSum += mapEven[toValidate[i]] ?? 0;
      }
    }

    const expected = String.fromCharCode(65 + ((oddSum + evenSum) % 26));
    return expected === control;
  },
  contextWords: ["codice fiscale", "cf"],
  baseConfidence: "medium",
  baseScore: 0.3,
};

export const IT_DRIVER_LICENSE: PiiPattern = {
  entityType: "IT_DRIVER_LICENSE",
  patterns: [
    /\b(?:[A-Z]{2}\d{7}[A-Z]|U1[BCDEFGHLJKMNPRSTUWYXZ0-9]{7}[A-Z])\b/gi,
  ],
  contextWords: ["patente", "patente di guida", "licenza", "licenza di guida"],
  baseConfidence: "low",
  baseScore: 0.2,
};

export const IT_VAT_CODE: PiiPattern = {
  entityType: "IT_VAT_CODE",
  patterns: [/\b\d{11}\b/g],
  validate: (match) => {
    const digits = match.replace(/[\s_]/g, "");
    if (digits.length !== 11) return false;
    if (digits === "00000000000") return false;

    let x = 0;
    let y = 0;
    for (let i = 0; i < 5; i++) {
      x += parseInt(digits[2 * i], 10);
      let tmpY = parseInt(digits[2 * i + 1], 10) * 2;
      if (tmpY > 9) tmpY -= 9;
      y += tmpY;
    }
    const t = (x + y) % 10;
    const c = (10 - t) % 10;
    return c === parseInt(digits[10], 10);
  },
  contextWords: ["piva", "partita iva", "pi"],
  baseConfidence: "low",
  baseScore: 0.1,
};

export const IT_PASSPORT: PiiPattern = {
  entityType: "IT_PASSPORT",
  patterns: [/\b[A-Z]{2}\d{7}\b/gi],
  contextWords: ["passaporto", "elettronico", "italiano", "viaggio", "documento"],
  baseConfidence: "low",
  baseScore: 0.01,
};

export const IT_IDENTITY_CARD: PiiPattern = {
  entityType: "IT_IDENTITY_CARD",
  patterns: [
    /\b[A-Z]{2}\s?\d{7}\b/gi,
    /\b\d{7}[A-Z]{2}\b/gi,
    /\b[A-Z]{2}\d{5}[A-Z]{2}\b/gi,
  ],
  contextWords: ["carta", "identità", "elettronica", "cie", "documento"],
  baseConfidence: "low",
  baseScore: 0.01,
};

// --- Poland ---

export const PL_PESEL: PiiPattern = {
  entityType: "PL_PESEL",
  patterns: [
    /\b\d{2}(?:[02468][1-9]|[13579][012])(?:0[1-9]|[12]\d|3[01])\d{5}\b/g,
  ],
  validate: (match) => {
    if (match.length !== 11) return false;
    const digits = match.split("").map(Number);
    const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let checksum = 0;
    for (let i = 0; i < 10; i++) {
      checksum += digits[i] * weights[i];
    }
    return (checksum % 10) === digits[10];
  },
  contextWords: ["pesel"],
  baseConfidence: "medium",
  baseScore: 0.4,
};

// --- Finland ---

export const FI_PERSONAL_IDENTITY_CODE: PiiPattern = {
  entityType: "FI_PERSONAL_IDENTITY_CODE",
  patterns: [
    /\b(\d{6})([+\-ABCDEFYXWVU])(\d{3})([0-9ABCDEFHJKLMNPRSTUVWXY])\b/g,
  ],
  validate: (match) => {
    if (match.length !== 11) return false;
    const datePart = match.slice(0, 6);
    const individual = match.slice(7, 10);
    const control = match[10];
    const validChars = "0123456789ABCDEFHJKLMNPRSTUVWXY";
    const num = parseInt(datePart + individual, 10);
    return validChars[num % 31] === control;
  },
  contextWords: ["hetu", "henkilötunnus", "personal identity code"],
  baseConfidence: "medium",
  baseScore: 0.5,
};

// --- Sweden ---

export const SE_PERSONNUMMER: PiiPattern = {
  entityType: "SE_PERSONNUMMER",
  patterns: [/\b(\d{6,8})([-+]?)\d{4}\b/g],
  validate: (match) => {
    const digits = match.replace(/[-+]/g, "");
    const last10 = digits.slice(-10);
    if (last10.length !== 10) return false;

    // Validate month/day
    const month = parseInt(last10.slice(2, 4), 10);
    let day = parseInt(last10.slice(4, 6), 10);
    if (day >= 61) day -= 60; // samordningsnummer
    if (month < 1 || month > 12 || day < 1 || day > 31) return false;

    // Luhn on 10 digits
    const nums = last10.split("").map(Number);
    const check = nums[9];
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      let d = nums[i];
      if (i % 2 === 0) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
    }
    return (sum + check) % 10 === 0;
  },
  contextWords: [
    "personnummer",
    "svenskt personnummer",
    "svensk id",
    "personal identity number",
    "samordningsnummer",
  ],
  baseConfidence: "medium",
  baseScore: 0.5,
};

// --- Germany ---

export const DE_TAX_ID: PiiPattern = {
  entityType: "DE_TAX_ID",
  patterns: [/\b[1-9]\d{10}\b/g],
  validate: (match) => {
    if (match.length !== 11 || !/^\d+$/.test(match)) return false;
    const digits = match.split("").map(Number);

    // All first 10 digits same = invalid
    if (new Set(digits.slice(0, 10)).size === 1) return false;

    // ISO 7064 Mod 11,10 checksum
    let product = 10;
    for (let i = 0; i < 10; i++) {
      let total = (digits[i] + product) % 10;
      if (total === 0) total = 10;
      product = (total * 2) % 11;
    }
    let check = 11 - product;
    if (check === 10) check = 0;
    return check === digits[10];
  },
  contextWords: [
    "steueridentifikationsnummer",
    "steuer-id",
    "steuerid",
    "idnr",
    "steuer-idnr",
    "steuernummer",
  ],
  baseConfidence: "medium",
  baseScore: 0.5,
};

export const DE_PASSPORT: PiiPattern = {
  entityType: "DE_PASSPORT",
  patterns: [
    /\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{7}[CFGHJKLMNPRTVWXYZ0-9]\b/g,
    /\bT\d{8}\b/g,
  ],
  contextWords: [
    "personalausweis",
    "ausweis",
    "reisepass",
    "pass",
    "dokumentennummer",
    "seriennummer",
  ],
  baseConfidence: "low",
  baseScore: 0.4,
};

/** All EU PII patterns */
export const EU_PATTERNS: PiiPattern[] = [
  ES_NIF,
  ES_NIE,
  IT_FISCAL_CODE,
  IT_DRIVER_LICENSE,
  IT_VAT_CODE,
  IT_PASSPORT,
  IT_IDENTITY_CARD,
  PL_PESEL,
  FI_PERSONAL_IDENTITY_CODE,
  SE_PERSONNUMMER,
  DE_TAX_ID,
  DE_PASSPORT,
];
