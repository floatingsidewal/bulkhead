/**
 * Database and data store secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const DATABASE_CONNECTION_STRING: SecretPattern = {
  secretType: "DATABASE_CONNECTION_STRING",
  patterns: [
    /(?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[^\s"']+/gi,
  ],
};

export const MONGODB_SRV: SecretPattern = {
  secretType: "MONGODB_SRV",
  patterns: [/mongodb\+srv:\/\/[^\s"']+/g],
};

export const REDIS_URL_WITH_PASSWORD: SecretPattern = {
  secretType: "REDIS_URL_WITH_PASSWORD",
  patterns: [/redis:\/\/:[^@\s]+@[^\s"']+/g],
};

export const ELASTICSEARCH_URL: SecretPattern = {
  secretType: "ELASTICSEARCH_URL",
  patterns: [/https?:\/\/[^:]+:[^@]+@[^/]*(?:elastic|es|elasticsearch)[^\s"']*/gi],
};

export const FIREBASE_KEY: SecretPattern = {
  secretType: "FIREBASE_KEY",
  patterns: [/(?:FIREBASE_API_KEY|FIREBASE_KEY)\s*[:=]\s*["']?(AIza[A-Za-z0-9_-]{35})["']?/g],
};

export const FIREBASE_URL: SecretPattern = {
  secretType: "FIREBASE_URL",
  patterns: [/https:\/\/[a-z0-9-]+\.firebaseio\.com/g],
};

export const SUPABASE_KEY: SecretPattern = {
  secretType: "SUPABASE_KEY",
  patterns: [
    /(?:SUPABASE_KEY|SUPABASE_ANON_KEY|SUPABASE_SERVICE_KEY)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]{100,})["']?/g,
  ],
};

export const PLANETSCALE_TOKEN: SecretPattern = {
  secretType: "PLANETSCALE_TOKEN",
  patterns: [/pscale_tkn_[A-Za-z0-9_-]{40,}/g],
};

export const PLANETSCALE_PASSWORD: SecretPattern = {
  secretType: "PLANETSCALE_PASSWORD",
  patterns: [/pscale_pw_[A-Za-z0-9_-]{40,}/g],
};

export const COCKROACHDB_CONNECTION: SecretPattern = {
  secretType: "COCKROACHDB_CONNECTION",
  patterns: [/(?:COCKROACH_URL|DATABASE_URL)\s*[:=]\s*["']?(postgresql:\/\/[^\s"']+\.cockroachlabs\.cloud[^\s"']*)["']?/g],
};

export const NEON_DB_TOKEN: SecretPattern = {
  secretType: "NEON_DB_TOKEN",
  patterns: [/(?:NEON_API_KEY|NEON_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const DATABASE_PATTERNS: SecretPattern[] = [
  DATABASE_CONNECTION_STRING,
  MONGODB_SRV,
  REDIS_URL_WITH_PASSWORD,
  ELASTICSEARCH_URL,
  FIREBASE_KEY,
  FIREBASE_URL,
  SUPABASE_KEY,
  PLANETSCALE_TOKEN,
  PLANETSCALE_PASSWORD,
  COCKROACHDB_CONNECTION,
  NEON_DB_TOKEN,
];
