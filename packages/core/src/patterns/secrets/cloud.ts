/**
 * Cloud provider secret patterns.
 * AWS patterns ported from HAI-Guardrails (MIT). See ATTRIBUTION.md.
 * Additional patterns derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

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

export const AWS_SESSION_TOKEN: SecretPattern = {
  secretType: "AWS_SESSION_TOKEN",
  patterns: [/(?:aws_session_token|AWS_SESSION_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})["']?/g],
  minEntropy: 4.0,
};

export const AWS_MWS_KEY: SecretPattern = {
  secretType: "AWS_MWS_KEY",
  patterns: [/amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g],
};

export const AZURE_CONNECTION_STRING: SecretPattern = {
  secretType: "AZURE_CONNECTION_STRING",
  patterns: [
    /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;?/g,
    /(?:AccountKey|SharedAccessKey|SharedAccessSignature)=[A-Za-z0-9+/=]{20,}/g,
  ],
};

export const AZURE_AD_CLIENT_SECRET: SecretPattern = {
  secretType: "AZURE_AD_CLIENT_SECRET",
  patterns: [/(?:client_secret|AZURE_CLIENT_SECRET)\s*[:=]\s*["']?([A-Za-z0-9~._-]{34,})["']?/g],
  minEntropy: 3.5,
};

export const AZURE_STORAGE_KEY: SecretPattern = {
  secretType: "AZURE_STORAGE_KEY",
  patterns: [/[A-Za-z0-9+/]{86}==/g],
  minEntropy: 5.0,
};

export const AZURE_FUNCTION_KEY: SecretPattern = {
  secretType: "AZURE_FUNCTION_KEY",
  patterns: [/(?:x-functions-key|functionkey)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/gi],
  minEntropy: 3.5,
};

export const GCP_SERVICE_ACCOUNT: SecretPattern = {
  secretType: "GCP_SERVICE_ACCOUNT",
  patterns: [/"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g],
};

export const GCP_API_KEY: SecretPattern = {
  secretType: "GCP_API_KEY",
  patterns: [/AIza[0-9A-Za-z_-]{35}/g],
};

export const GCP_OAUTH_SECRET: SecretPattern = {
  secretType: "GCP_OAUTH_SECRET",
  patterns: [/GOCSPX-[A-Za-z0-9_-]{28}/g],
};

export const IBM_CLOUD_API_KEY: SecretPattern = {
  secretType: "IBM_CLOUD_API_KEY",
  patterns: [/(?:ibm[-_]?(?:cloud)?[-_]?api[-_]?key)\s*[:=]\s*["']?([A-Za-z0-9_-]{44})["']?/gi],
};

export const IBM_COS_HMAC: SecretPattern = {
  secretType: "IBM_COS_HMAC",
  patterns: [/(?:cos_hmac_keys|ibm_cos)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi],
  minEntropy: 3.5,
};

export const DIGITALOCEAN_TOKEN: SecretPattern = {
  secretType: "DIGITALOCEAN_TOKEN",
  patterns: [
    /dop_v1_[a-f0-9]{64}/g,
    /doo_v1_[a-f0-9]{64}/g,
    /dor_v1_[a-f0-9]{64}/g,
  ],
};

export const DIGITALOCEAN_SPACES_KEY: SecretPattern = {
  secretType: "DIGITALOCEAN_SPACES_KEY",
  patterns: [/(?:SPACES_ACCESS_KEY_ID|DO_SPACES_KEY)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/g],
};

export const LINODE_TOKEN: SecretPattern = {
  secretType: "LINODE_TOKEN",
  patterns: [/(?:LINODE_TOKEN|LINODE_API_TOKEN)\s*[:=]\s*["']?([a-f0-9]{64})["']?/g],
};

export const VULTR_API_KEY: SecretPattern = {
  secretType: "VULTR_API_KEY",
  patterns: [/(?:VULTR_API_KEY)\s*[:=]\s*["']?([A-Z0-9]{36})["']?/g],
};

export const ORACLE_CLOUD_KEY: SecretPattern = {
  secretType: "ORACLE_CLOUD_KEY",
  patterns: [/(?:OCI_API_KEY|ORACLE_CLOUD_KEY)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40,})["']?/g],
  minEntropy: 4.0,
};

export const ALIBABA_CLOUD_KEY: SecretPattern = {
  secretType: "ALIBABA_CLOUD_KEY",
  patterns: [/LTAI[A-Za-z0-9]{12,20}/g],
};

export const CLOUD_PATTERNS: SecretPattern[] = [
  AWS_ACCESS_KEY,
  AWS_SECRET_KEY,
  AWS_SESSION_TOKEN,
  AWS_MWS_KEY,
  AZURE_CONNECTION_STRING,
  AZURE_AD_CLIENT_SECRET,
  AZURE_STORAGE_KEY,
  AZURE_FUNCTION_KEY,
  GCP_SERVICE_ACCOUNT,
  GCP_API_KEY,
  GCP_OAUTH_SECRET,
  IBM_CLOUD_API_KEY,
  IBM_COS_HMAC,
  DIGITALOCEAN_TOKEN,
  DIGITALOCEAN_SPACES_KEY,
  LINODE_TOKEN,
  VULTR_API_KEY,
  ORACLE_CLOUD_KEY,
  ALIBABA_CLOUD_KEY,
];
