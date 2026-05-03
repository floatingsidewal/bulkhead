/**
 * Default synthesizers for common PII entity types.
 *
 * Each synthesizer:
 *   - Is **pure** (deterministic given input) and **side-effect-free**.
 *   - Reads the per-call `consistencyMap` first. If `original` already
 *     has a replacement, it returns that — never minting a fresh one
 *     for the same input within a call.
 *   - Uses **IETF / RFC documentation reservations** for synthetic values
 *     where they exist (example.com, 192.0.2.0/24, RFC 5612 MAC, GB82
 *     IBAN, Stripe test cards). These are guaranteed safe and identifiable
 *     as test data by automated scanners.
 *   - Hashes `original` to pick a stable index into a name list / number
 *     range, so the same input always produces the same output across
 *     calls within one engine session.
 *
 * Replacement contract: synthesizers receive only the matched substring
 * (eg. `"john.smith@contoso.com"`), not the surrounding context. They
 * MUST return a string of comparable shape to the input (eg. an email
 * address replaced with another email address).
 */

import type { Synthesizer } from "../types";

// ---------------------------------------------------------------------------
// Stable name list (frozen — changing the order changes synthesizer outputs)
// ---------------------------------------------------------------------------

const FIRST_NAMES = [
  "Alex", "Jordan", "Sam", "Morgan", "Casey", "Riley", "Quinn",
  "Avery", "Blake", "Drew", "Cameron", "Reese", "Logan", "Jamie",
  "Hayden", "Skyler", "Rowan", "Emerson", "Finley", "Harper",
  "Kai", "Lane", "Marlowe", "Noel", "Parker", "River", "Sage",
  "Tatum", "Wren", "Ari", "Bellamy", "Charlie", "Dakota", "Ellis",
  "Frankie", "Greer", "Indigo", "Jules", "Kennedy", "Linden",
  "Murphy", "Nico", "Oakley", "Phoenix", "Quincy", "Remy", "Sasha",
  "Theo", "Vesper", "Wynn",
];

const LAST_NAMES = [
  "Rivera", "Chen", "Patel", "Kim", "Brooks", "Nguyen", "Taylor",
  "Davis", "Thompson", "Martinez", "Anderson", "Thomas", "Jackson",
  "White", "Harris", "Martin", "Garcia", "Robinson", "Clark", "Lewis",
  "Walker", "Hall", "Allen", "Young", "King", "Wright", "Scott",
  "Green", "Adams", "Baker", "Nelson", "Hill", "Campbell", "Mitchell",
  "Carter", "Roberts", "Phillips", "Evans", "Turner", "Diaz", "Parker",
  "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Murphy",
  "Cook", "Rogers",
];

// ---------------------------------------------------------------------------
// Hash helper — stable, deterministic 32-bit FNV-1a
// ---------------------------------------------------------------------------

/**
 * FNV-1a 32-bit hash. Stable across Node versions and platforms.
 * Used to deterministically select indices into the name lists, IP ranges,
 * etc., so the same input always produces the same synthesized output.
 */
function fnv1a(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  // Coerce to unsigned 32-bit
  return hash >>> 0;
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

/**
 * Replace with `firstname.lastname@example.com` (RFC 2606 reserved).
 * Stable across calls for the same original.
 */
const synthEmail: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  const h = fnv1a(original);
  const first = FIRST_NAMES[h % FIRST_NAMES.length].toLowerCase();
  const last = LAST_NAMES[(h >>> 8) % LAST_NAMES.length].toLowerCase();
  return `${first}.${last}@example.com`;
};

// ---------------------------------------------------------------------------
// Person name
// ---------------------------------------------------------------------------

/**
 * Replace with a synthetic "First Last" pair drawn from the name lists.
 * The first/last name combination is hashed off the original so multiple
 * mentions of the same name in one document map to the same synthetic
 * (via the consistency map).
 */
const synthPersonName: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  const h = fnv1a(original);
  const first = FIRST_NAMES[h % FIRST_NAMES.length];
  const last = LAST_NAMES[(h >>> 8) % LAST_NAMES.length];
  return `${first} ${last}`;
};

// ---------------------------------------------------------------------------
// Phone number
// ---------------------------------------------------------------------------

/**
 * Replace with `+1-555-010-XXXX` where XXXX is the last 4 digits of the
 * FNV-1a hash mod 10000. The 555-01XX range is reserved for fictitious
 * numbers in NANP. Same input → same output.
 */
const synthPhone: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  const h = fnv1a(original);
  const last4 = String(h % 10000).padStart(4, "0");
  return `+1-555-010-${last4}`;
};

// ---------------------------------------------------------------------------
// Credit card
// ---------------------------------------------------------------------------

/**
 * Replace with a Stripe-published test card number.
 * Picks based on the original's leading digit so a Visa stays Visa-shaped,
 * Mastercard stays Mastercard-shaped, etc. — preserves brand-detection
 * behavior in downstream consumers.
 */
const STRIPE_TEST_CARDS: Record<string, string> = {
  "4": "4242424242424242", // Visa
  "5": "5555555555554444", // Mastercard
  "3": "378282246310005", // Amex
  "6": "6011111111111117", // Discover
};

const synthCreditCard: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  const digits = original.replace(/[^0-9]/g, "");
  const lead = digits.charAt(0);
  return STRIPE_TEST_CARDS[lead] ?? "4242424242424242";
};

// ---------------------------------------------------------------------------
// IP address
// ---------------------------------------------------------------------------

/**
 * Replace with an address from RFC 5737 documentation prefixes
 * (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Last octet hashed
 * off original for stability within consistency map.
 */
const DOC_PREFIXES = ["192.0.2", "198.51.100", "203.0.113"];

const synthIpAddress: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  const h = fnv1a(original);
  const prefix = DOC_PREFIXES[h % DOC_PREFIXES.length];
  const lastOctet = (h >>> 8) % 254 + 1; // 1-254, avoid .0 and .255
  return `${prefix}.${lastOctet}`;
};

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------

/**
 * Replace the host with `example.com` (RFC 2606), preserve scheme and path.
 * If the URL doesn't parse, fall back to literal `https://example.com`.
 */
const synthUrl: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  try {
    const u = new URL(original);
    u.hostname = "example.com";
    return u.toString();
  } catch {
    return "https://example.com/";
  }
};

// ---------------------------------------------------------------------------
// IBAN code
// ---------------------------------------------------------------------------

/**
 * Replace with the well-known UK test IBAN. Stable across all inputs;
 * IBAN format is high-structure so brand-preservation isn't applicable.
 */
const synthIban: Synthesizer = () => "GB82 WEST 1234 5698 7654 32";

// ---------------------------------------------------------------------------
// MAC address
// ---------------------------------------------------------------------------

/**
 * Replace with `00:00:5E:00:53:XX` from the RFC 5612 documentation MAC
 * range. Last octet hashed for stability.
 */
const synthMac: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  const h = fnv1a(original);
  const last = (h % 256).toString(16).padStart(2, "0").toUpperCase();
  return `00:00:5E:00:53:${last}`;
};

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------

/**
 * Replace with `00000000-redacted-XXXX-0000-NNNNNNNNNNNN` where the XXXX
 * and trailing 12-hex segment are derived from the input hash for
 * stability. Format is intentionally non-canonical so downstream PII
 * scanners flag it as `TEST_DATA_GUID` rather than as a real GUID.
 */
const synthGuid: Synthesizer = (original, ctx) => {
  const cached = ctx.consistencyMap.get(original);
  if (cached) return cached;
  const h = fnv1a(original);
  const seq = (h % 0xffff).toString(16).padStart(4, "0");
  // 12-hex tail derived from a second hash pass for variety
  const tail = ((h * 0x01000193) >>> 0).toString(16).padStart(8, "0");
  return `00000000-redacted-${seq}-0000-${tail}0000`;
};

// ---------------------------------------------------------------------------
// Crypto address (best-effort: use a documented test BTC vanity address)
// ---------------------------------------------------------------------------

const synthCrypto: Synthesizer = () => "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";

// ---------------------------------------------------------------------------
// Registered defaults
// ---------------------------------------------------------------------------

/**
 * Default synthesizer registry. Keys match the `entityType` strings
 * emitted by the bundled PII patterns (see `src/patterns/pii/`).
 *
 * Consumers extend or override via `engine.setSynthesizers({ ... })`.
 */
export const DEFAULT_SYNTHESIZERS: Record<string, Synthesizer> = {
  EMAIL_ADDRESS: synthEmail,
  PERSON_NAME: synthPersonName,
  // BERT-NER often produces these — alias to PERSON_NAME synthesizer
  PER: synthPersonName,
  PHONE_NUMBER: synthPhone,
  US_PHONE: synthPhone,
  UK_PHONE: synthPhone,
  CREDIT_CARD: synthCreditCard,
  IP_ADDRESS: synthIpAddress,
  URL: synthUrl,
  IBAN_CODE: synthIban,
  MAC_ADDRESS: synthMac,
  CRYPTO: synthCrypto,
  // Generic GUID synthesizer — many entity types use it
  GUID: synthGuid,
};

// Re-export individuals for testing and selective override
export {
  synthEmail,
  synthPersonName,
  synthPhone,
  synthCreditCard,
  synthIpAddress,
  synthUrl,
  synthIban,
  synthMac,
  synthCrypto,
  synthGuid,
  fnv1a as _fnv1aForTest,
};
