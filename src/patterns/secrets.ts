/**
 * Secret/credential detection patterns.
 * Inspired by HAI-Guardrails. See ATTRIBUTION.md.
 */

import type { SecretPattern } from "../types";

export const AWS_ACCESS_KEY: SecretPattern = {
  secretType: "AWS_ACCESS_KEY",
  patterns: [/(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/g],
};

export const AWS_SECRET_KEY: SecretPattern = {
  secretType: "AWS_SECRET_KEY",
  patterns: [
    /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
  ],
  minEntropy: 4.5,
};

export const GITHUB_TOKEN: SecretPattern = {
  secretType: "GITHUB_TOKEN",
  patterns: [
    /ghp_[A-Za-z0-9]{36}/g,
    /gho_[A-Za-z0-9]{36}/g,
    /ghu_[A-Za-z0-9]{36}/g,
    /ghs_[A-Za-z0-9]{36}/g,
    /ghr_[A-Za-z0-9]{36}/g,
    /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g,
  ],
};

export const GITLAB_TOKEN: SecretPattern = {
  secretType: "GITLAB_TOKEN",
  patterns: [
    /glpat-[A-Za-z0-9\-_]{20}/g,
    /glcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_\-]{20}/g,
    /gldt-[A-Za-z0-9_\-]{20}/g,
    /glft-[A-Za-z0-9_\-]{20}/g,
    /glsoat-[A-Za-z0-9_\-]{20}/g,
    /GR1348941[A-Za-z0-9_\-]{20}/g,
  ],
};

export const AZURE_CONNECTION_STRING: SecretPattern = {
  secretType: "AZURE_CONNECTION_STRING",
  patterns: [
    /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;?/g,
    /(?:AccountKey|SharedAccessKey|SharedAccessSignature)=[A-Za-z0-9+/=]{20,}/g,
  ],
};

export const GCP_SERVICE_ACCOUNT: SecretPattern = {
  secretType: "GCP_SERVICE_ACCOUNT",
  patterns: [/"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g],
};

export const JWT_TOKEN: SecretPattern = {
  secretType: "JWT_TOKEN",
  patterns: [
    /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  ],
};

export const PRIVATE_KEY: SecretPattern = {
  secretType: "PRIVATE_KEY",
  patterns: [
    /-----BEGIN (?:RSA |EC |ED25519 |OPENSSH )?PRIVATE KEY-----/g,
  ],
};

export const NPM_TOKEN: SecretPattern = {
  secretType: "NPM_TOKEN",
  patterns: [/npm_[A-Za-z0-9]{36}/g],
};

export const SLACK_TOKEN: SecretPattern = {
  secretType: "SLACK_TOKEN",
  patterns: [/xox[bporas]-[A-Za-z0-9-]{10,}/g],
};

export const STRIPE_KEY: SecretPattern = {
  secretType: "STRIPE_KEY",
  patterns: [
    /sk_live_[A-Za-z0-9]{20,}/g,
    /rk_live_[A-Za-z0-9]{20,}/g,
  ],
};

export const DATABASE_CONNECTION_STRING: SecretPattern = {
  secretType: "DATABASE_CONNECTION_STRING",
  patterns: [
    /(?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[^\s"']+/gi,
  ],
};

export const SENDGRID_KEY: SecretPattern = {
  secretType: "SENDGRID_KEY",
  patterns: [/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g],
};

export const TWILIO_KEY: SecretPattern = {
  secretType: "TWILIO_KEY",
  patterns: [/SK[0-9a-fA-F]{32}/g],
};

export const OPENAI_KEY: SecretPattern = {
  secretType: "OPENAI_KEY",
  patterns: [/sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g],
};

export const ANTHROPIC_KEY: SecretPattern = {
  secretType: "ANTHROPIC_KEY",
  patterns: [/sk-ant-[A-Za-z0-9_-]{40,}/g],
};

export const GENERIC_HIGH_ENTROPY: SecretPattern = {
  secretType: "GENERIC_SECRET",
  patterns: [
    // Assignments like API_KEY="..." or token: "..."
    /(?:api[_-]?key|secret|token|password|passwd|credential|auth)[_\s]*[:=]\s*["']([A-Za-z0-9+/=_\-]{16,})["']/gi,
  ],
  minEntropy: 3.5,
};

/** All secret patterns */
export const ALL_SECRET_PATTERNS: SecretPattern[] = [
  AWS_ACCESS_KEY,
  AWS_SECRET_KEY,
  GITHUB_TOKEN,
  GITLAB_TOKEN,
  AZURE_CONNECTION_STRING,
  GCP_SERVICE_ACCOUNT,
  JWT_TOKEN,
  PRIVATE_KEY,
  NPM_TOKEN,
  SLACK_TOKEN,
  STRIPE_KEY,
  DATABASE_CONNECTION_STRING,
  SENDGRID_KEY,
  TWILIO_KEY,
  OPENAI_KEY,
  ANTHROPIC_KEY,
  GENERIC_HIGH_ENTROPY,
];
