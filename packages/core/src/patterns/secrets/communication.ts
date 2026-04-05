/**
 * Communication platform secret patterns.
 * Slack pattern ported from HAI-Guardrails (MIT). See ATTRIBUTION.md.
 * Additional patterns from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const SLACK_TOKEN: SecretPattern = {
  secretType: "SLACK_TOKEN",
  patterns: [/xox[bporas]-[A-Za-z0-9-]{10,}/g],
};

export const SLACK_WEBHOOK: SecretPattern = {
  secretType: "SLACK_WEBHOOK",
  patterns: [/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/g],
};

export const SLACK_APP_TOKEN: SecretPattern = {
  secretType: "SLACK_APP_TOKEN",
  patterns: [/xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+/g],
};

export const DISCORD_TOKEN: SecretPattern = {
  secretType: "DISCORD_TOKEN",
  patterns: [/(?:DISCORD_TOKEN|DISCORD_BOT_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})["']?/g],
};

export const DISCORD_WEBHOOK: SecretPattern = {
  secretType: "DISCORD_WEBHOOK",
  patterns: [/https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g],
};

export const TELEGRAM_BOT_TOKEN: SecretPattern = {
  secretType: "TELEGRAM_BOT_TOKEN",
  patterns: [/[0-9]{8,10}:[A-Za-z0-9_-]{35}/g],
};

export const TWILIO_KEY: SecretPattern = {
  secretType: "TWILIO_KEY",
  patterns: [/SK[0-9a-fA-F]{32}/g],
};

export const TWILIO_ACCOUNT_SID: SecretPattern = {
  secretType: "TWILIO_ACCOUNT_SID",
  patterns: [/AC[a-f0-9]{32}/g],
};

export const TWILIO_AUTH_TOKEN: SecretPattern = {
  secretType: "TWILIO_AUTH_TOKEN",
  patterns: [/(?:TWILIO_AUTH_TOKEN)\s*[:=]\s*["']?([a-f0-9]{32})["']?/g],
};

export const SENDGRID_KEY: SecretPattern = {
  secretType: "SENDGRID_KEY",
  patterns: [/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g],
};

export const MAILGUN_KEY: SecretPattern = {
  secretType: "MAILGUN_KEY",
  patterns: [
    /key-[A-Za-z0-9]{32}/g,
    /(?:MAILGUN_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9-]{32,})["']?/g,
  ],
};

export const MAILCHIMP_KEY: SecretPattern = {
  secretType: "MAILCHIMP_KEY",
  patterns: [/[a-f0-9]{32}-us[0-9]{1,2}/g],
};

export const POSTMARK_TOKEN: SecretPattern = {
  secretType: "POSTMARK_TOKEN",
  patterns: [/(?:POSTMARK_API_TOKEN|POSTMARK_SERVER_TOKEN)\s*[:=]\s*["']?([a-f0-9-]{36})["']?/g],
};

export const TEAMS_WEBHOOK: SecretPattern = {
  secretType: "TEAMS_WEBHOOK",
  patterns: [/https:\/\/[a-z0-9-]+\.webhook\.office\.com\/webhookb2\/[A-Za-z0-9-]+/g],
};

export const INTERCOM_TOKEN: SecretPattern = {
  secretType: "INTERCOM_TOKEN",
  patterns: [/(?:INTERCOM_TOKEN|INTERCOM_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9_=-]{20,})["']?/g],
  minEntropy: 3.5,
};

export const COMMUNICATION_PATTERNS: SecretPattern[] = [
  SLACK_TOKEN,
  SLACK_WEBHOOK,
  SLACK_APP_TOKEN,
  DISCORD_TOKEN,
  DISCORD_WEBHOOK,
  TELEGRAM_BOT_TOKEN,
  TWILIO_KEY,
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  SENDGRID_KEY,
  MAILGUN_KEY,
  MAILCHIMP_KEY,
  POSTMARK_TOKEN,
  TEAMS_WEBHOOK,
  INTERCOM_TOKEN,
];
