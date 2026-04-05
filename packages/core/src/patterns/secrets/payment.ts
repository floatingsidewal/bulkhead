/**
 * Payment platform secret patterns.
 * Derived from GitLeaks (MIT) and public documentation.
 */

import type { SecretPattern } from "../../types";

export const STRIPE_KEY: SecretPattern = {
  secretType: "STRIPE_KEY",
  patterns: [
    /sk_live_[A-Za-z0-9]{20,}/g,
    /rk_live_[A-Za-z0-9]{20,}/g,
    /sk_test_[A-Za-z0-9]{20,}/g,
    /rk_test_[A-Za-z0-9]{20,}/g,
  ],
};

export const STRIPE_WEBHOOK_SECRET: SecretPattern = {
  secretType: "STRIPE_WEBHOOK_SECRET",
  patterns: [/whsec_[A-Za-z0-9]{32,}/g],
};

export const SQUARE_ACCESS_TOKEN: SecretPattern = {
  secretType: "SQUARE_ACCESS_TOKEN",
  patterns: [
    /sq0atp-[A-Za-z0-9_-]{22}/g,
    /EAAAE[A-Za-z0-9]{50,}/g,
  ],
};

export const SQUARE_OAUTH_SECRET: SecretPattern = {
  secretType: "SQUARE_OAUTH_SECRET",
  patterns: [/sq0csp-[A-Za-z0-9_-]{43}/g],
};

export const PAYPAL_CLIENT_SECRET: SecretPattern = {
  secretType: "PAYPAL_CLIENT_SECRET",
  patterns: [/(?:PAYPAL_CLIENT_SECRET|PAYPAL_SECRET)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const PAYPAL_BRAINTREE_TOKEN: SecretPattern = {
  secretType: "PAYPAL_BRAINTREE_TOKEN",
  patterns: [/access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}/g],
};

export const BRAINTREE_KEY: SecretPattern = {
  secretType: "BRAINTREE_KEY",
  patterns: [/(?:BRAINTREE_(?:PUBLIC|PRIVATE)_KEY)\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?/g],
};

export const ADYEN_API_KEY: SecretPattern = {
  secretType: "ADYEN_API_KEY",
  patterns: [/(?:ADYEN_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/g],
  minEntropy: 3.5,
};

export const SHOPIFY_TOKEN: SecretPattern = {
  secretType: "SHOPIFY_TOKEN",
  patterns: [
    /shpat_[a-fA-F0-9]{32}/g,
    /shpca_[a-fA-F0-9]{32}/g,
    /shppa_[a-fA-F0-9]{32}/g,
    /shpss_[a-fA-F0-9]{32}/g,
  ],
};

export const PLAID_KEY: SecretPattern = {
  secretType: "PLAID_KEY",
  patterns: [
    /(?:PLAID_CLIENT_ID)\s*[:=]\s*["']?([a-f0-9]{24})["']?/g,
    /(?:PLAID_SECRET)\s*[:=]\s*["']?([a-f0-9]{30})["']?/g,
    /access-(?:sandbox|development|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
  ],
};

export const PAYMENT_PATTERNS: SecretPattern[] = [
  STRIPE_KEY,
  STRIPE_WEBHOOK_SECRET,
  SQUARE_ACCESS_TOKEN,
  SQUARE_OAUTH_SECRET,
  PAYPAL_CLIENT_SECRET,
  PAYPAL_BRAINTREE_TOKEN,
  BRAINTREE_KEY,
  ADYEN_API_KEY,
  SHOPIFY_TOKEN,
  PLAID_KEY,
];
