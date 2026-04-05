import type { LlmProvider } from "@bulkhead/core";
import type { ServerConfig } from "./config";

const DEFAULT_TIMEOUT_MS = 10_000;

export function createLlmProvider(config: ServerConfig): LlmProvider | undefined {
  const timeoutMs = config.llmTimeout ?? DEFAULT_TIMEOUT_MS;

  switch (config.llmProvider) {
    case "openai":
      console.log("LLM provider: OpenAI (gpt-4o-mini)");
      return withRetry(createOpenAIProvider(config.llmApiKey, timeoutMs));
    case "anthropic":
      console.log("LLM provider: Anthropic (claude-haiku-4-5)");
      return withRetry(createAnthropicProvider(config.llmApiKey, timeoutMs));
    case "custom":
      console.log(`LLM provider: Custom (${config.llmEndpoint})`);
      return withRetry(createCustomProvider(config.llmEndpoint, config.llmApiKey, timeoutMs));
    default:
      return undefined;
  }
}

/** Wrap a provider with single-retry on network errors (not 4xx/5xx) */
function withRetry(provider: LlmProvider): LlmProvider {
  return async (prompt: string): Promise<string> => {
    try {
      return await provider(prompt);
    } catch (err) {
      // Retry on network/timeout errors, not on API errors (4xx/5xx)
      if (err instanceof Error && isRetryableError(err)) {
        console.warn(`LLM call failed (${err.message}), retrying once...`);
        return provider(prompt);
      }
      throw err;
    }
  };
}

function isRetryableError(err: Error): boolean {
  const msg = err.message.toLowerCase();
  return (
    msg.includes("timeout") ||
    msg.includes("aborted") ||
    msg.includes("econnrefused") ||
    msg.includes("econnreset") ||
    msg.includes("fetch failed") ||
    msg.includes("network")
  );
}

function fetchWithTimeout(url: string, options: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

function createOpenAIProvider(apiKey: string, timeoutMs: number): LlmProvider {
  return async (prompt: string): Promise<string> => {
    const response = await fetchWithTimeout(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [{ role: "user", content: prompt }],
          max_tokens: 100,
          temperature: 0,
        }),
      },
      timeoutMs
    );

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status}`);
    }

    const data = (await response.json()) as any;
    return data.choices[0].message.content;
  };
}

function createAnthropicProvider(apiKey: string, timeoutMs: number): LlmProvider {
  return async (prompt: string): Promise<string> => {
    const response = await fetchWithTimeout(
      "https://api.anthropic.com/v1/messages",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 100,
          messages: [{ role: "user", content: prompt }],
        }),
      },
      timeoutMs
    );

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status}`);
    }

    const data = (await response.json()) as any;
    return data.content[0].text;
  };
}

function createCustomProvider(endpoint: string, apiKey: string, timeoutMs: number): LlmProvider {
  return async (prompt: string): Promise<string> => {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
    }

    const response = await fetchWithTimeout(
      endpoint,
      {
        method: "POST",
        headers,
        body: JSON.stringify({
          messages: [{ role: "user", content: prompt }],
          max_tokens: 100,
        }),
      },
      timeoutMs
    );

    if (!response.ok) {
      throw new Error(`Custom LLM API error: ${response.status}`);
    }

    const data = (await response.json()) as any;
    return data.choices?.[0]?.message?.content ?? data.content?.[0]?.text ?? data.text ?? String(data);
  };
}
