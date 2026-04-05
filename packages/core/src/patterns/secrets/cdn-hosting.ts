/**
 * CDN and hosting platform secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const CLOUDFLARE_API_KEY: SecretPattern = {
  secretType: "CLOUDFLARE_API_KEY",
  patterns: [
    /(?:CLOUDFLARE_API_KEY|CF_API_KEY)\s*[:=]\s*["']?([a-f0-9]{37})["']?/g,
    /(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{40})["']?/g,
  ],
};

export const CLOUDFLARE_CA_KEY: SecretPattern = {
  secretType: "CLOUDFLARE_CA_KEY",
  patterns: [/v1\.0-[a-f0-9]{24}-[a-f0-9]{146}/g],
};

export const FASTLY_API_KEY: SecretPattern = {
  secretType: "FASTLY_API_KEY",
  patterns: [/(?:FASTLY_API_TOKEN|FASTLY_KEY)\s*[:=]\s*["']?([A-Za-z0-9_-]{32})["']?/g],
};

export const NETLIFY_TOKEN: SecretPattern = {
  secretType: "NETLIFY_TOKEN",
  patterns: [/(?:NETLIFY_AUTH_TOKEN|NETLIFY_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const VERCEL_TOKEN: SecretPattern = {
  secretType: "VERCEL_TOKEN",
  patterns: [/(?:VERCEL_TOKEN|NOW_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9]{24})["']?/g],
};

export const HEROKU_API_KEY: SecretPattern = {
  secretType: "HEROKU_API_KEY",
  patterns: [
    /(?:HEROKU_API_KEY)\s*[:=]\s*["']?([a-f0-9-]{36})["']?/g,
    /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
  ],
};

export const RENDER_TOKEN: SecretPattern = {
  secretType: "RENDER_TOKEN",
  patterns: [/rnd_[A-Za-z0-9]{32,}/g],
};

export const FLY_IO_TOKEN: SecretPattern = {
  secretType: "FLY_IO_TOKEN",
  patterns: [/(?:FLY_ACCESS_TOKEN|FLY_API_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const RAILWAY_TOKEN: SecretPattern = {
  secretType: "RAILWAY_TOKEN",
  patterns: [/(?:RAILWAY_TOKEN)\s*[:=]\s*["']?([a-f0-9-]{36})["']?/g],
};

export const SURGE_TOKEN: SecretPattern = {
  secretType: "SURGE_TOKEN",
  patterns: [/(?:SURGE_TOKEN|SURGE_LOGIN)\s*[:=]\s*["']?([A-Za-z0-9._-]{20,})["']?/g],
  minEntropy: 3.5,
};

export const CDN_HOSTING_PATTERNS: SecretPattern[] = [
  CLOUDFLARE_API_KEY,
  CLOUDFLARE_CA_KEY,
  FASTLY_API_KEY,
  NETLIFY_TOKEN,
  VERCEL_TOKEN,
  HEROKU_API_KEY,
  RENDER_TOKEN,
  FLY_IO_TOKEN,
  RAILWAY_TOKEN,
  SURGE_TOKEN,
];
