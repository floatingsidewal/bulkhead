/**
 * Temporal-policy transformation for detected timestamps.
 *
 * Implements RFC-002. Given a list of detections from one or more
 * guards plus a TemporalPolicy, produces replacement strings for any
 * `DATE_TIME` detections according to the policy's mode:
 *
 *   - `preserve`:             no-op (returns empty replacement map)
 *   - `rebase-year-zero`:     rewrites the year to `0001`, preserves
 *                              month/day/time. Operates on the surface
 *                              text via simple regex; does NOT require
 *                              parseable Dates, so it works on
 *                              ambiguous formats like "04/30/2026".
 *   - `rebase-relative-to-earliest`:
 *                              parses ISO 8601 detections, finds the
 *                              earliest, rewrites all to be relative to
 *                              `0001-01-01T00:00:00.000Z`. Preserves
 *                              relative offsets in milliseconds (or the
 *                              configured precision). Non-ISO timestamps
 *                              fall through unchanged.
 *
 * Output is NOT applied directly to text here. Instead, this module
 * returns a `Map<original, rebasedReplacement>` that gets merged into
 * the engine's per-call consistency map BEFORE guards run. Guards then
 * pick up the rebased values via the existing computeReplacement
 * cache-first lookup. This composes cleanly with synthesize mode and
 * avoids a separate redaction pass.
 *
 * Format-coverage notes:
 *   - ISO 8601:           "2026-04-30T05:37:33Z" / "2026-04-30T05:37:33.123+05:30"
 *   - yyyy-mm-dd:         "2026-04-30"
 *   - mm/dd/yyyy:         "04/30/2026"
 *
 * For year-zero rebasing, all three formats are handled.
 * For relative rebasing, only ISO 8601 timestamps are parsed; other
 * formats are skipped (their detections still appear in the output map
 * but with their original value as the "rebased" replacement, so they
 * pass through unchanged through the engine's pipeline).
 */

import type { Detection } from "../types";
import type { LocalizedDateOrder } from "../types";
import type { TemporalPolicy } from "./types";

/** UTC year-zero anchor. ISO 8601 valid; ECMAScript Date round-trips it.
 *  NOTE: `Date.UTC(1, 0, 1)` is interpreted as year 1901 because legacy
 *  year-shorthand maps 0-99 to 1900-1999. We parse the ISO string directly
 *  to get an actual year-0001 epoch. */
const YEAR_ZERO_ANCHOR_ISO = "0001-01-01T00:00:00.000Z";
const YEAR_ZERO_ANCHOR_MS = Date.parse(YEAR_ZERO_ANCHOR_ISO);

export interface ParsedTemporalDate {
  date: Date;
  format: "iso" | "ymd" | "localized";
}

export interface TemporalReplacementPlan {
  replacements: Map<string, string>;
  temporalAnchor?: string;
}

function validCalendarDate(year: number, month: number, day: number): boolean {
  if (month < 1 || month > 12 || day < 1) return false;
  const probe = new Date(`${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}T00:00:00.000Z`);
  return (
    !Number.isNaN(probe.getTime()) &&
    probe.getUTCFullYear() === year &&
    probe.getUTCMonth() === month - 1 &&
    probe.getUTCDate() === day
  );
}

/**
 * Parse only documented date forms. This intentionally avoids host locale
 * parsing and validates calendar fields before asking Date to parse a
 * timestamp. Two-digit years are never accepted.
 */
export function parseTemporalDate(
  value: string,
  localizedDateOrder: LocalizedDateOrder = "reject-ambiguous",
): ParsedTemporalDate | null {
  const iso = value.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?(Z|[+-](?:0\d|1\d|2[0-3]):[0-5]\d)$/,
  );
  if (iso) {
    const [, y, m, d, hour, minute, second] = iso;
    if (
      !validCalendarDate(Number(y), Number(m), Number(d)) ||
      Number(hour) > 23 ||
      Number(minute) > 59 ||
      Number(second) > 59
    ) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : { date, format: "iso" };
  }

  const ymd = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (ymd) {
    const [, y, m, d] = ymd;
    if (!validCalendarDate(Number(y), Number(m), Number(d))) return null;
    return { date: new Date(`${value}T00:00:00.000Z`), format: "ymd" };
  }

  const localized = value.match(/^(\d{1,2})[/.](\d{1,2})[/.](\d{4})$/);
  if (!localized) return null;
  const [, first, second, yearText] = localized;
  const firstNumber = Number(first);
  const secondNumber = Number(second);
  const year = Number(yearText);
  const ambiguous = firstNumber <= 12 && secondNumber <= 12;
  if (ambiguous && localizedDateOrder === "reject-ambiguous") return null;
  // A component above 12 makes the order unambiguous, regardless of the
  // caller's preference. The preference only decides genuinely ambiguous
  // values such as 07/08/2026.
  const order =
    firstNumber > 12 ? "dmy" : secondNumber > 12 ? "mdy" : localizedDateOrder === "dmy" ? "dmy" : "mdy";
  const month = order === "mdy" ? firstNumber : secondNumber;
  const day = order === "mdy" ? secondNumber : firstNumber;
  if (!validCalendarDate(year, month, day)) return null;
  return {
    date: new Date(`${yearText}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}T00:00:00.000Z`),
    format: "localized",
  };
}

/**
 * Produce document-wide temporal replacements. Every DATE_TIME detection is
 * either transformed or mapped to the explicit safe fallback; no parse
 * failure can seed a no-op consistency entry.
 */
export function planTemporalReplacements(
  detections: Detection[],
  policy: TemporalPolicy | undefined,
  localizedDateOrder: LocalizedDateOrder = "reject-ambiguous",
  fallback = "[REDACTED-DATE_TIME]",
): TemporalReplacementPlan {
  const replacements = new Map<string, string>();
  const dates = detections.filter((d) => d.entityType === "DATE_TIME");
  if (dates.length === 0) return { replacements };

  const parsed = dates.map((d) => ({ detection: d, parsed: parseTemporalDate(d.text, localizedDateOrder) }));
  const safe = (entry: (typeof parsed)[number]) => {
    if (!entry.parsed) replacements.set(entry.detection.text, fallback);
  };

  if (!policy || policy.mode === "preserve") {
    for (const entry of parsed) safe(entry);
    return { replacements };
  }
  if (policy.mode === "rebase-year-zero") {
    for (const entry of parsed) {
      if (!entry.parsed) {
        safe(entry);
        continue;
      }
      const rebased = rebaseYearZero(entry.detection.text);
      replacements.set(
        entry.detection.text,
        parseTemporalDate(rebased, localizedDateOrder) ? rebased : fallback,
      );
    }
    return { replacements };
  }

  const parseable = parsed.filter(
    (entry): entry is { detection: Detection; parsed: ParsedTemporalDate } => entry.parsed !== null,
  );
  for (const entry of parsed) safe(entry);
  if (parseable.length === 0) return { replacements };
  const earliest = Math.min(...parseable.map((entry) => entry.parsed.date.getTime()));
  for (const entry of parseable) {
    replacements.set(
      entry.detection.text,
      formatYearZeroOffset(entry.parsed.date.getTime() - earliest, policy.precision),
    );
  }
  return { replacements, temporalAnchor: new Date(earliest).toISOString() };
}

/**
 * Round a Date down to a coarser unit. Used to optionally reduce the
 * precision of rebased timestamps for additional privacy.
 */
function roundToPrecision(date: Date, precision: TemporalPolicy["precision"]): Date {
  const d = new Date(date.getTime());
  switch (precision) {
    case "second":
      d.setUTCMilliseconds(0);
      break;
    case "minute":
      d.setUTCMilliseconds(0);
      d.setUTCSeconds(0);
      break;
    case "hour":
      d.setUTCMilliseconds(0);
      d.setUTCSeconds(0);
      d.setUTCMinutes(0);
      break;
    case "day":
      d.setUTCMilliseconds(0);
      d.setUTCSeconds(0);
      d.setUTCMinutes(0);
      d.setUTCHours(0);
      break;
    case "ms":
    default:
      // No rounding
      break;
  }
  return d;
}

/**
 * Rewrite the year portion of an ISO-8601-shaped or numeric date string
 * to `0001`. Preserves month/day/time-of-day exactly. Operates lexically
 * via regex on the surface form.
 *
 * Handles:
 *   - 2026-04-30T05:37:33Z       -> 0001-04-30T05:37:33Z
 *   - 2026-04-30                 -> 0001-04-30
 *   - 04/30/2026                 -> 04/30/0001
 *   - 30/04/2026                 -> 30/04/0001
 *
 * Year is recognized as the 4-digit segment and replaced once. If the
 * pattern doesn't match any known shape, the original is returned
 * unchanged.
 */
export function rebaseYearZero(original: string): string {
  // ISO 8601: yyyy-mm-ddT...
  const isoMatch = original.match(/^(\d{4})(-\d{2}-\d{2}T.+)$/);
  if (isoMatch) {
    return "0001" + isoMatch[2];
  }
  // yyyy-mm-dd (date-only)
  const dateOnly = original.match(/^(\d{4})(-\d{2}-\d{2})$/);
  if (dateOnly) {
    return "0001" + dateOnly[2];
  }
  // mm/dd/yyyy or dd/mm/yyyy (year is the trailing 4-digit segment)
  const slashed = original.match(/^(.+[/.\-])(\d{4})$/);
  if (slashed) {
    return slashed[1] + "0001";
  }
  // Unknown — return unchanged so the engine can fall back to other handling
  return original;
}

/**
 * Parse an ISO 8601 timestamp into a Date. Returns null if not parseable.
 * Strict-ish: requires a 4-digit year + month + day at minimum.
 */
function parseIso(s: string): Date | null {
  // Must look like yyyy-mm-dd at minimum
  if (!/^\d{4}-\d{2}-\d{2}/.test(s)) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Format a Date as an ISO 8601 string at year-zero anchor + offset.
 * `offsetMs` is the elapsed time from the original earliest timestamp.
 * Output: "0001-01-DDTHH:MM:SS.mmmZ" (or earlier days if offset is large).
 *
 * For multi-month offsets we do calendar arithmetic — Date objects
 * starting from 0001 handle this correctly in V8.
 */
function formatYearZeroOffset(offsetMs: number, precision: TemporalPolicy["precision"]): string {
  const d = new Date(YEAR_ZERO_ANCHOR_MS + offsetMs);
  return roundToPrecision(d, precision).toISOString();
}

/**
 * Compute the rebased-replacement map for the requested temporal policy.
 *
 * Returns a Map<original, replacement>. Only DATE_TIME detections are
 * processed; other entity types are not present in the result.
 *
 * For `mode: "preserve"` returns an empty Map.
 *
 * The engine merges this map into the per-call consistency map BEFORE
 * any guard runs. When guards subsequently hit a DATE_TIME detection
 * during redaction, computeReplacement reads the cached rebased value
 * and uses it — no separate pass needed.
 */
export function computeTemporalReplacements(
  detections: Detection[],
  policy: TemporalPolicy | undefined,
): Map<string, string> {
  const out = new Map<string, string>();
  if (!policy || policy.mode === "preserve") return out;

  const dateDetections = detections.filter((d) => d.entityType === "DATE_TIME");
  if (dateDetections.length === 0) return out;

  if (policy.mode === "rebase-year-zero") {
    for (const d of dateDetections) {
      out.set(d.text, rebaseYearZero(d.text));
    }
    return out;
  }

  if (policy.mode === "rebase-relative-to-earliest") {
    // Parse each detection. Non-ISO entries pass through unchanged.
    const parsed: Array<{ original: string; date: Date }> = [];
    for (const d of dateDetections) {
      const parsedDate = parseIso(d.text);
      if (parsedDate) {
        parsed.push({ original: d.text, date: parsedDate });
      } else {
        // Non-ISO: leave unchanged. The detection still gets counted as
        // a date but doesn't participate in relative rebasing because
        // we can't reliably parse it.
        out.set(d.text, d.text);
      }
    }

    if (parsed.length === 0) return out;

    // Find the earliest. Stable sort isn't required; min works.
    let earliestMs = Infinity;
    for (const p of parsed) {
      if (p.date.getTime() < earliestMs) earliestMs = p.date.getTime();
    }

    for (const p of parsed) {
      const offsetMs = p.date.getTime() - earliestMs;
      out.set(p.original, formatYearZeroOffset(offsetMs, policy.precision));
    }
    return out;
  }

  // Unknown mode — pass through.
  return out;
}
