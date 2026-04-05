import type { LlmProvider } from "@bulkhead/core";
import type { ServerConfig } from "./config";

export function createLlmProvider(config: ServerConfig): LlmProvider | undefined {
  switch (config.llmProvider) {
    case "openai":
      return createOpenAIProvider(config.llmApiKey);
    case "anthropic":
      return createAnthropicProvider(config.llmApiKey);
    case "custom":
      return createCustomProvider(config.llmEndpoint, config.llmApiKey);
    default:
      return undefined;
  }
}

function createOpenAIProvider(apiKey: string): LlmProvider {
  return async (prompt: string): Promise<string> => {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
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
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status}`);
    }

    const data = (await response.json()) as any;
    return data.choices[0].message.content;
  };
}

function createAnthropicProvider(apiKey: string): LlmProvider {
  return async (prompt: string): Promise<string> => {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
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
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status}`);
    }

    const data = (await response.json()) as any;
    return data.content[0].text;
  };
}

function createCustomProvider(endpoint: string, apiKey: string): LlmProvider {
  return async (prompt: string): Promise<string> => {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
    }

    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        messages: [{ role: "user", content: prompt }],
        max_tokens: 100,
      }),
    });

    if (!response.ok) {
      throw new Error(`Custom LLM API error: ${response.status}`);
    }

    const data = (await response.json()) as any;
    // Try common response shapes
    return data.choices?.[0]?.message?.content ?? data.content?.[0]?.text ?? data.text ?? String(data);
  };
}
