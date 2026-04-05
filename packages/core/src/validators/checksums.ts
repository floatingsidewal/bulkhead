/**
 * Checksum validation algorithms ported from Microsoft Presidio.
 * See ATTRIBUTION.md for details.
 */

/** Luhn algorithm for credit card validation */
export function luhn(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length === 0) return false;

  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/** IBAN mod-97 checksum validation */
export function ibanMod97(iban: string): boolean {
  const cleaned = iban.replace(/[\s-]/g, "").toUpperCase();
  if (cleaned.length < 4) return false;

  // Move first 4 chars to end
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);

  // Convert letters to numbers (A=10, B=11, ..., Z=35)
  let numeric = "";
  for (const char of rearranged) {
    const code = char.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      numeric += (code - 55).toString();
    } else {
      numeric += char;
    }
  }

  // Mod 97 in chunks (to avoid BigInt for most cases)
  let remainder = 0;
  for (const char of numeric) {
    remainder = (remainder * 10 + parseInt(char, 10)) % 97;
  }

  return remainder === 1;
}

/** ABA routing number checksum: weights [3,7,1,3,7,1,3,7,1] mod 10 */
export function abaRouting(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 9) return false;

  const weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(digits[i], 10) * weights[i];
  }
  return sum % 10 === 0;
}

/** NPI Luhn checksum with "80840" prefix per CMS spec */
export function npiLuhn(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 10) return false;

  const prefixed = "80840" + digits;
  const nums = prefixed.split("").map(Number);

  let checksum = 0;
  for (let i = nums.length - 1; i >= 0; i--) {
    const pos = nums.length - 1 - i;
    let n = nums[i];
    if (pos % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    checksum += n;
  }
  return checksum % 10 === 0;
}

/** DEA medical license checksum (modified Luhn) */
export function deaChecksum(value: string): boolean {
  const cleaned = value.replace(/[\s-]/g, "");
  if (cleaned.length < 3) return false;

  const numericPart = cleaned.slice(2);
  const digits = numericPart.split("").map(Number);
  if (digits.some(isNaN)) return false;

  const check = digits.pop()!;
  const even = digits.filter((_, i) => i % 2 === 0);
  const odd = digits.filter((_, i) => i % 2 === 1);

  const sum =
    2 * even.reduce((a, b) => a + b, 0) + odd.reduce((a, b) => a + b, 0);
  return (sum - check) % 10 === 0;
}

/** Shannon entropy calculation for secret detection */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of value) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

/** US SSN validation — rejects known invalid patterns */
export function validateSsn(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length !== 9) return false;

  // All same digit
  if (digits.split("").every((c) => c === digits[0])) return false;

  // Group cannot be all zeros
  if (digits.slice(3, 5) === "00") return false;
  if (digits.slice(5) === "0000") return false;

  // Known invalid prefixes
  const invalidPrefixes = ["000", "666", "123456789", "98765432", "078051120"];
  for (const prefix of invalidPrefixes) {
    if (digits.startsWith(prefix)) return false;
  }

  // Area number cannot start with 9 (reserved for ITIN)
  if (digits[0] === "9") return false;

  return true;
}

/** Validate MAC address — reject broadcast and null */
export function validateMac(value: string): boolean {
  const cleaned = value.replace(/[:\-.]/g, "").toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(cleaned)) return false;
  if (cleaned === "FFFFFFFFFFFF") return false; // broadcast
  if (cleaned === "000000000000") return false; // null
  return true;
}
