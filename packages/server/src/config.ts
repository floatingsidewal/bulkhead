import { type BulkheadConfig, DEFAULT_CONFIG } from "@floatingsidewal/bulkhead-core";

export interface ServerConfig {
  port: number;
  host: string;
  logLevel: "info" | "warn" | "error" | "silent";
  corsOrigin: string | false;
  maxBodySize: number;
  apiKey: string;
  llmProvider: "none" | "openai" | "anthropic" | "custom";
  llmApiKey: string;
  llmEndpoint: string;
  llmTimeout: number;
}

export interface FullConfig {
  server: ServerConfig;
  engine: BulkheadConfig;
}

function envBool(key: string, fallback: boolean): boolean {
  const val = process.env[key];
  if (val === undefined) return fallback;
  return val === "true" || val === "1";
}

function envInt(key: string, fallback: number): number {
  const val = process.env[key];
  if (val === undefined) return fallback;
  const parsed = parseInt(val, 10);
  return isNaN(parsed) ? fallback : parsed;
}

function envFloat(key: string, fallback: number): number {
  const val = process.env[key];
  if (val === undefined) return fallback;
  const parsed = parseFloat(val);
  return isNaN(parsed) ? fallback : parsed;
}

export function loadConfig(): FullConfig {
  return {
    server: {
      port: envInt("BULKHEAD_PORT", 3000),
      host: process.env.BULKHEAD_HOST ?? "0.0.0.0",
      logLevel: (process.env.BULKHEAD_LOG_LEVEL as ServerConfig["logLevel"]) ?? "info",
      corsOrigin: process.env.BULKHEAD_CORS_ORIGIN || false,
      maxBodySize: envInt("BULKHEAD_MAX_BODY_SIZE", 1_048_576), // 1MB
      apiKey: process.env.BULKHEAD_API_KEY ?? "",
      llmProvider: (process.env.BULKHEAD_LLM_PROVIDER as ServerConfig["llmProvider"]) ?? "none",
      llmApiKey: process.env.BULKHEAD_LLM_API_KEY ?? "",
      llmEndpoint: process.env.BULKHEAD_LLM_ENDPOINT ?? "",
      llmTimeout: envInt("BULKHEAD_LLM_TIMEOUT", 10_000),
    },
    engine: {
      enabled: envBool("BULKHEAD_ENABLED", DEFAULT_CONFIG.enabled),
      debounceMs: DEFAULT_CONFIG.debounceMs,
      guards: {
        pii: { enabled: envBool("BULKHEAD_GUARDS_PII_ENABLED", DEFAULT_CONFIG.guards.pii.enabled) },
        secret: { enabled: envBool("BULKHEAD_GUARDS_SECRET_ENABLED", DEFAULT_CONFIG.guards.secret.enabled) },
        injection: { enabled: envBool("BULKHEAD_GUARDS_INJECTION_ENABLED", DEFAULT_CONFIG.guards.injection.enabled) },
        contentSafety: { enabled: envBool("BULKHEAD_GUARDS_CONTENT_SAFETY_ENABLED", DEFAULT_CONFIG.guards.contentSafety.enabled) },
      },
      cascade: {
        escalationThreshold: envFloat("BULKHEAD_CASCADE_ESCALATION_THRESHOLD", DEFAULT_CONFIG.cascade.escalationThreshold),
        contextSentences: envInt("BULKHEAD_CASCADE_CONTEXT_SENTENCES", DEFAULT_CONFIG.cascade.contextSentences),
        modelEnabled: envBool("BULKHEAD_CASCADE_MODEL_ENABLED", DEFAULT_CONFIG.cascade.modelEnabled),
        modelId: process.env.BULKHEAD_CASCADE_MODEL_ID ?? DEFAULT_CONFIG.cascade.modelId,
      },
    },
  };
}
