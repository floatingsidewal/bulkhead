/**
 * SaaS platform secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const SALESFORCE_TOKEN: SecretPattern = {
  secretType: "SALESFORCE_TOKEN",
  patterns: [/(?:SALESFORCE_TOKEN|SF_ACCESS_TOKEN|SFDC_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9!]{40,})["']?/g],
  minEntropy: 3.5,
};

export const HUBSPOT_API_KEY: SecretPattern = {
  secretType: "HUBSPOT_API_KEY",
  patterns: [
    /(?:HUBSPOT_API_KEY|HAPI_KEY)\s*[:=]\s*["']?([a-f0-9-]{36})["']?/g,
    /pat-(?:na|eu)1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
  ],
};

export const ZENDESK_TOKEN: SecretPattern = {
  secretType: "ZENDESK_TOKEN",
  patterns: [/(?:ZENDESK_TOKEN|ZENDESK_API_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9]{40})["']?/g],
};

export const DATADOG_API_KEY: SecretPattern = {
  secretType: "DATADOG_API_KEY",
  patterns: [
    /(?:DD_API_KEY|DATADOG_API_KEY)\s*[:=]\s*["']?([a-f0-9]{32})["']?/g,
    /(?:DD_APP_KEY|DATADOG_APP_KEY)\s*[:=]\s*["']?([a-f0-9]{40})["']?/g,
  ],
};

export const NEW_RELIC_KEY: SecretPattern = {
  secretType: "NEW_RELIC_KEY",
  patterns: [
    /NRAK-[A-Z0-9]{27}/g,
    /(?:NEW_RELIC_LICENSE_KEY|NEWRELIC_KEY)\s*[:=]\s*["']?([a-f0-9]{40})["']?/g,
    /NRII-[A-Za-z0-9_-]{32}/g,
    /NRIQ-[A-Za-z0-9_-]{32}/g,
  ],
};

export const PAGERDUTY_KEY: SecretPattern = {
  secretType: "PAGERDUTY_KEY",
  patterns: [/(?:PAGERDUTY_TOKEN|PD_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9_+-]{20})["']?/g],
};

export const LAUNCHDARKLY_KEY: SecretPattern = {
  secretType: "LAUNCHDARKLY_KEY",
  patterns: [
    /(?:sdk|mob|api)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
  ],
};

export const SENTRY_DSN: SecretPattern = {
  secretType: "SENTRY_DSN",
  patterns: [/https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io\/[0-9]+/g],
};

export const SENTRY_AUTH_TOKEN: SecretPattern = {
  secretType: "SENTRY_AUTH_TOKEN",
  patterns: [
    /sntrys_[A-Za-z0-9]{60,}/g,
    /(?:SENTRY_AUTH_TOKEN)\s*[:=]\s*["']?([a-f0-9]{64})["']?/g,
  ],
};

export const SEGMENT_KEY: SecretPattern = {
  secretType: "SEGMENT_KEY",
  patterns: [/(?:SEGMENT_WRITE_KEY|SEGMENT_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?/g],
};

export const AIRTABLE_KEY: SecretPattern = {
  secretType: "AIRTABLE_KEY",
  patterns: [
    /key[A-Za-z0-9]{14}/g,
    /pat[A-Za-z0-9]{14}\.[a-f0-9]{64}/g,
  ],
};

export const NOTION_TOKEN: SecretPattern = {
  secretType: "NOTION_TOKEN",
  patterns: [
    /secret_[A-Za-z0-9]{43}/g,
    /ntn_[A-Za-z0-9]{40,}/g,
  ],
};

export const ASANA_TOKEN: SecretPattern = {
  secretType: "ASANA_TOKEN",
  patterns: [/(?:ASANA_TOKEN|ASANA_ACCESS_TOKEN)\s*[:=]\s*["']?([0-9]\/[0-9]{16}:[A-Za-z0-9]{32})["']?/g],
};

export const JIRA_TOKEN: SecretPattern = {
  secretType: "JIRA_TOKEN",
  patterns: [/(?:JIRA_TOKEN|JIRA_API_TOKEN|ATLASSIAN_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9]{24,})["']?/g],
  minEntropy: 3.5,
};

export const LINEAR_API_KEY: SecretPattern = {
  secretType: "LINEAR_API_KEY",
  patterns: [/lin_api_[A-Za-z0-9]{40}/g],
};

export const CONTENTFUL_TOKEN: SecretPattern = {
  secretType: "CONTENTFUL_TOKEN",
  patterns: [/(?:CONTENTFUL_ACCESS_TOKEN|CONTENTFUL_DELIVERY_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{43})["']?/g],
};

export const ALGOLIA_KEY: SecretPattern = {
  secretType: "ALGOLIA_KEY",
  patterns: [/(?:ALGOLIA_ADMIN_KEY|ALGOLIA_API_KEY)\s*[:=]\s*["']?([a-f0-9]{32})["']?/g],
};

export const SAAS_PATTERNS: SecretPattern[] = [
  SALESFORCE_TOKEN,
  HUBSPOT_API_KEY,
  ZENDESK_TOKEN,
  DATADOG_API_KEY,
  NEW_RELIC_KEY,
  PAGERDUTY_KEY,
  LAUNCHDARKLY_KEY,
  SENTRY_DSN,
  SENTRY_AUTH_TOKEN,
  SEGMENT_KEY,
  AIRTABLE_KEY,
  NOTION_TOKEN,
  ASANA_TOKEN,
  JIRA_TOKEN,
  LINEAR_API_KEY,
  CONTENTFUL_TOKEN,
  ALGOLIA_KEY,
];
