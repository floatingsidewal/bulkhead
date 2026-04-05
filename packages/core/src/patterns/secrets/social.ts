/**
 * Social media platform secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const TWITTER_API_KEY: SecretPattern = {
  secretType: "TWITTER_API_KEY",
  patterns: [
    /(?:TWITTER_API_KEY|TWITTER_CONSUMER_KEY)\s*[:=]\s*["']?([A-Za-z0-9]{25})["']?/g,
  ],
};

export const TWITTER_API_SECRET: SecretPattern = {
  secretType: "TWITTER_API_SECRET",
  patterns: [
    /(?:TWITTER_API_SECRET|TWITTER_CONSUMER_SECRET)\s*[:=]\s*["']?([A-Za-z0-9]{50})["']?/g,
  ],
};

export const TWITTER_BEARER_TOKEN: SecretPattern = {
  secretType: "TWITTER_BEARER_TOKEN",
  patterns: [/AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}/g],
};

export const FACEBOOK_TOKEN: SecretPattern = {
  secretType: "FACEBOOK_TOKEN",
  patterns: [
    /EAA[A-Za-z0-9]{100,}/g,
    /(?:FACEBOOK_TOKEN|FB_ACCESS_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9|_-]{40,})["']?/g,
  ],
};

export const FACEBOOK_SECRET: SecretPattern = {
  secretType: "FACEBOOK_SECRET",
  patterns: [/(?:FACEBOOK_SECRET|FB_APP_SECRET)\s*[:=]\s*["']?([a-f0-9]{32})["']?/g],
};

export const INSTAGRAM_TOKEN: SecretPattern = {
  secretType: "INSTAGRAM_TOKEN",
  patterns: [/(?:INSTAGRAM_TOKEN|IG_ACCESS_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9.]{100,})["']?/g],
  minEntropy: 3.5,
};

export const LINKEDIN_SECRET: SecretPattern = {
  secretType: "LINKEDIN_SECRET",
  patterns: [/(?:LINKEDIN_CLIENT_SECRET|LINKEDIN_SECRET)\s*[:=]\s*["']?([A-Za-z0-9]{16})["']?/g],
};

export const YOUTUBE_API_KEY: SecretPattern = {
  secretType: "YOUTUBE_API_KEY",
  patterns: [/(?:YOUTUBE_API_KEY)\s*[:=]\s*["']?(AIza[A-Za-z0-9_-]{35})["']?/g],
};

export const TIKTOK_TOKEN: SecretPattern = {
  secretType: "TIKTOK_TOKEN",
  patterns: [/(?:TIKTOK_TOKEN|TIKTOK_ACCESS_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9._-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const PINTEREST_TOKEN: SecretPattern = {
  secretType: "PINTEREST_TOKEN",
  patterns: [/(?:PINTEREST_TOKEN|PINTEREST_ACCESS_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const SOCIAL_PATTERNS: SecretPattern[] = [
  TWITTER_API_KEY,
  TWITTER_API_SECRET,
  TWITTER_BEARER_TOKEN,
  FACEBOOK_TOKEN,
  FACEBOOK_SECRET,
  INSTAGRAM_TOKEN,
  LINKEDIN_SECRET,
  YOUTUBE_API_KEY,
  TIKTOK_TOKEN,
  PINTEREST_TOKEN,
];
