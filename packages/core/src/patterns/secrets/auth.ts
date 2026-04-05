/**
 * Authentication platform secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const AUTH0_CLIENT_SECRET: SecretPattern = {
  secretType: "AUTH0_CLIENT_SECRET",
  patterns: [/(?:AUTH0_CLIENT_SECRET)\s*[:=]\s*["']?([A-Za-z0-9_-]{32,})["']?/g],
  minEntropy: 3.5,
};

export const AUTH0_MANAGEMENT_TOKEN: SecretPattern = {
  secretType: "AUTH0_MANAGEMENT_TOKEN",
  patterns: [/(?:AUTH0_MANAGEMENT_API_TOKEN|AUTH0_TOKEN)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]{100,})["']?/g],
};

export const OKTA_TOKEN: SecretPattern = {
  secretType: "OKTA_TOKEN",
  patterns: [
    /(?:OKTA_TOKEN|OKTA_API_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{42})["']?/g,
    /00[A-Za-z0-9_-]{40}/g,
  ],
};

export const CLERK_SECRET_KEY: SecretPattern = {
  secretType: "CLERK_SECRET_KEY",
  patterns: [/sk_(?:live|test)_[A-Za-z0-9]{24,}/g],
};

export const CLERK_PUBLISHABLE_KEY: SecretPattern = {
  secretType: "CLERK_PUBLISHABLE_KEY",
  patterns: [/pk_(?:live|test)_[A-Za-z0-9]{24,}/g],
};

export const FIREBASE_AUTH_KEY: SecretPattern = {
  secretType: "FIREBASE_AUTH_KEY",
  patterns: [/(?:FIREBASE_AUTH_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{100,})["']?/g],
  minEntropy: 4.0,
};

export const SUPABASE_SERVICE_KEY: SecretPattern = {
  secretType: "SUPABASE_SERVICE_KEY",
  patterns: [/(?:SUPABASE_SERVICE_ROLE_KEY)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]{100,})["']?/g],
};

export const STYTCH_SECRET: SecretPattern = {
  secretType: "STYTCH_SECRET",
  patterns: [/secret-(?:live|test)-[A-Za-z0-9_-]{36,}/g],
};

export const PROPELAUTH_KEY: SecretPattern = {
  secretType: "PROPELAUTH_KEY",
  patterns: [/(?:PROPELAUTH_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const KEYCLOAK_SECRET: SecretPattern = {
  secretType: "KEYCLOAK_SECRET",
  patterns: [/(?:KEYCLOAK_CLIENT_SECRET|KC_CLIENT_SECRET)\s*[:=]\s*["']?([A-Za-z0-9-]{36})["']?/g],
};

export const AUTH_PATTERNS: SecretPattern[] = [
  AUTH0_CLIENT_SECRET,
  AUTH0_MANAGEMENT_TOKEN,
  OKTA_TOKEN,
  CLERK_SECRET_KEY,
  CLERK_PUBLISHABLE_KEY,
  FIREBASE_AUTH_KEY,
  SUPABASE_SERVICE_KEY,
  STYTCH_SECRET,
  PROPELAUTH_KEY,
  KEYCLOAK_SECRET,
];
