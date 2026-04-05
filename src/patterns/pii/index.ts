/**
 * PII Pattern Registry — aggregates all regional patterns.
 * Patterns ported from Microsoft Presidio. See ATTRIBUTION.md.
 */

import type { PiiPattern } from "../../types";
import { GENERIC_PATTERNS } from "./generic";
import { US_PATTERNS } from "./us";
import { UK_PATTERNS } from "./uk";
import { EU_PATTERNS } from "./eu";
import { APAC_PATTERNS } from "./apac";

export { GENERIC_PATTERNS } from "./generic";
export { US_PATTERNS } from "./us";
export { UK_PATTERNS } from "./uk";
export { EU_PATTERNS } from "./eu";
export { APAC_PATTERNS } from "./apac";

/** All available PII patterns */
export const ALL_PII_PATTERNS: PiiPattern[] = [
  ...GENERIC_PATTERNS,
  ...US_PATTERNS,
  ...UK_PATTERNS,
  ...EU_PATTERNS,
  ...APAC_PATTERNS,
];

/** Get patterns by entity type */
export function getPatternsByEntity(entityType: string): PiiPattern | undefined {
  return ALL_PII_PATTERNS.find((p) => p.entityType === entityType);
}

/** Get all available entity type names */
export function getAllEntityTypes(): string[] {
  return ALL_PII_PATTERNS.map((p) => p.entityType);
}
