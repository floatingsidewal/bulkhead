/**
 * Source control platform secret patterns.
 * GitHub/GitLab patterns ported from HAI-Guardrails (MIT). See ATTRIBUTION.md.
 * Additional patterns from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

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

export const GITHUB_APP_TOKEN: SecretPattern = {
  secretType: "GITHUB_APP_TOKEN",
  patterns: [/(?:ghu|ghs)_[A-Za-z0-9]{36}/g],
};

export const GITHUB_FINE_GRAINED_TOKEN: SecretPattern = {
  secretType: "GITHUB_FINE_GRAINED_TOKEN",
  patterns: [/github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g],
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

export const GITLAB_PIPELINE_TOKEN: SecretPattern = {
  secretType: "GITLAB_PIPELINE_TOKEN",
  patterns: [/glptt-[A-Za-z0-9]{20}/g],
};

export const BITBUCKET_APP_PASSWORD: SecretPattern = {
  secretType: "BITBUCKET_APP_PASSWORD",
  patterns: [/(?:BITBUCKET_APP_PASSWORD|BB_APP_PASSWORD)\s*[:=]\s*["']?([A-Za-z0-9]{18,})["']?/g],
  minEntropy: 3.5,
};

export const BITBUCKET_CLIENT_SECRET: SecretPattern = {
  secretType: "BITBUCKET_CLIENT_SECRET",
  patterns: [/(?:BITBUCKET_CLIENT_SECRET|BB_CLIENT_SECRET)\s*[:=]\s*["']?([A-Za-z0-9_-]{32,})["']?/g],
  minEntropy: 3.5,
};

export const AZURE_DEVOPS_TOKEN: SecretPattern = {
  secretType: "AZURE_DEVOPS_TOKEN",
  patterns: [/(?:AZURE_DEVOPS_PAT|ADO_TOKEN|SYSTEM_ACCESSTOKEN)\s*[:=]\s*["']?([A-Za-z0-9]{52,})["']?/g],
  minEntropy: 4.0,
};

export const GITEA_TOKEN: SecretPattern = {
  secretType: "GITEA_TOKEN",
  patterns: [/(?:GITEA_TOKEN)\s*[:=]\s*["']?([a-f0-9]{40})["']?/g],
};

export const SOURCE_CONTROL_PATTERNS: SecretPattern[] = [
  GITHUB_TOKEN,
  GITHUB_APP_TOKEN,
  GITHUB_FINE_GRAINED_TOKEN,
  GITLAB_TOKEN,
  GITLAB_PIPELINE_TOKEN,
  BITBUCKET_APP_PASSWORD,
  BITBUCKET_CLIENT_SECRET,
  AZURE_DEVOPS_TOKEN,
  GITEA_TOKEN,
];
