/**
 * Secret pattern registry — aggregates all category patterns.
 *
 * Pattern sources:
 * - HAI-Guardrails (MIT): AWS, GitHub, GitLab, Slack, JWT, Private Key, Generic
 * - GitLeaks (MIT): CI/CD, SaaS, Infrastructure, CDN, Social, and others
 * - Public documentation: AI/ML, Auth, Payment, Database providers
 *
 * See ATTRIBUTION.md for full attribution details.
 */

import type { SecretPattern } from "../../types";
import { CLOUD_PATTERNS } from "./cloud";
import { SOURCE_CONTROL_PATTERNS } from "./source-control";
import { CICD_PATTERNS } from "./cicd";
import { COMMUNICATION_PATTERNS } from "./communication";
import { PAYMENT_PATTERNS } from "./payment";
import { DATABASE_PATTERNS } from "./database";
import { INFRASTRUCTURE_PATTERNS } from "./infrastructure";
import { SAAS_PATTERNS } from "./saas";
import { AI_ML_PATTERNS } from "./ai-ml";
import { AUTH_PATTERNS } from "./auth";
import { CDN_HOSTING_PATTERNS } from "./cdn-hosting";
import { SOCIAL_PATTERNS } from "./social";
import { GENERIC_PATTERNS } from "./generic";

// Re-export categories for selective use
export { CLOUD_PATTERNS } from "./cloud";
export { SOURCE_CONTROL_PATTERNS } from "./source-control";
export { CICD_PATTERNS } from "./cicd";
export { COMMUNICATION_PATTERNS } from "./communication";
export { PAYMENT_PATTERNS } from "./payment";
export { DATABASE_PATTERNS } from "./database";
export { INFRASTRUCTURE_PATTERNS } from "./infrastructure";
export { SAAS_PATTERNS } from "./saas";
export { AI_ML_PATTERNS } from "./ai-ml";
export { AUTH_PATTERNS } from "./auth";
export { CDN_HOSTING_PATTERNS } from "./cdn-hosting";
export { SOCIAL_PATTERNS } from "./social";
export { GENERIC_PATTERNS } from "./generic";

/** All secret patterns across all categories */
export const ALL_SECRET_PATTERNS: SecretPattern[] = [
  ...CLOUD_PATTERNS,
  ...SOURCE_CONTROL_PATTERNS,
  ...CICD_PATTERNS,
  ...COMMUNICATION_PATTERNS,
  ...PAYMENT_PATTERNS,
  ...DATABASE_PATTERNS,
  ...INFRASTRUCTURE_PATTERNS,
  ...SAAS_PATTERNS,
  ...AI_ML_PATTERNS,
  ...AUTH_PATTERNS,
  ...CDN_HOSTING_PATTERNS,
  ...SOCIAL_PATTERNS,
  ...GENERIC_PATTERNS,
];
