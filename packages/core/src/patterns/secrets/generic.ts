/**
 * Generic secret patterns — catch-all detectors.
 * Inspired by HAI-Guardrails (MIT). See ATTRIBUTION.md.
 */

import type { SecretPattern } from "../../types";

export const JWT_TOKEN: SecretPattern = {
  secretType: "JWT_TOKEN",
  patterns: [
    /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  ],
};

export const PRIVATE_KEY: SecretPattern = {
  secretType: "PRIVATE_KEY",
  patterns: [
    /-----BEGIN (?:RSA |EC |ED25519 |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
  ],
};

export const NPM_TOKEN: SecretPattern = {
  secretType: "NPM_TOKEN",
  patterns: [
    /npm_[A-Za-z0-9]{36}/g,
    /\/\/registry\.npmjs\.org\/:_authToken=[A-Za-z0-9-]+/g,
  ],
};

export const PYPI_TOKEN: SecretPattern = {
  secretType: "PYPI_TOKEN",
  patterns: [/pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g],
};

export const RUBYGEMS_KEY: SecretPattern = {
  secretType: "RUBYGEMS_KEY",
  patterns: [/rubygems_[a-f0-9]{48}/g],
};

export const NUGET_KEY: SecretPattern = {
  secretType: "NUGET_KEY",
  patterns: [/oy2[A-Za-z0-9]{43}/g],
};

export const CRATES_IO_TOKEN: SecretPattern = {
  secretType: "CRATES_IO_TOKEN",
  patterns: [/cio[A-Za-z0-9]{32}/g],
};

export const GENERIC_HIGH_ENTROPY: SecretPattern = {
  secretType: "GENERIC_SECRET",
  patterns: [
    /(?:api[_-]?key|secret|token|password|passwd|credential|auth)[_\s]*[:=]\s*["']([A-Za-z0-9+/=_\-]{16,})["']/gi,
  ],
  minEntropy: 3.5,
};

export const GENERIC_BEARER_TOKEN: SecretPattern = {
  secretType: "BEARER_TOKEN",
  patterns: [
    /(?:Authorization|Bearer)\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9._~+/=-]{20,})["']?/g,
  ],
  minEntropy: 3.5,
};

export const BASIC_AUTH_HEADER: SecretPattern = {
  secretType: "BASIC_AUTH",
  patterns: [
    /(?:Authorization)\s*[:=]\s*["']?Basic\s+([A-Za-z0-9+/=]{20,})["']?/g,
  ],
};

export const GENERIC_PATTERNS: SecretPattern[] = [
  JWT_TOKEN,
  PRIVATE_KEY,
  NPM_TOKEN,
  PYPI_TOKEN,
  RUBYGEMS_KEY,
  NUGET_KEY,
  CRATES_IO_TOKEN,
  GENERIC_HIGH_ENTROPY,
  GENERIC_BEARER_TOKEN,
  BASIC_AUTH_HEADER,
];
