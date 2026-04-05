/**
 * AI/ML platform secret patterns.
 * OpenAI/Anthropic patterns from original Bulkhead.
 * Additional patterns from public documentation.
 */

import type { SecretPattern } from "../../types";

export const OPENAI_KEY: SecretPattern = {
  secretType: "OPENAI_KEY",
  patterns: [
    /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
    /sk-proj-[A-Za-z0-9_-]{40,}/g,
    /sk-[A-Za-z0-9_-]{40,}/g,
  ],
};

export const ANTHROPIC_KEY: SecretPattern = {
  secretType: "ANTHROPIC_KEY",
  patterns: [/sk-ant-[A-Za-z0-9_-]{40,}/g],
};

export const COHERE_KEY: SecretPattern = {
  secretType: "COHERE_KEY",
  patterns: [
    /(?:COHERE_API_KEY|CO_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9]{40})["']?/g,
  ],
};

export const HUGGINGFACE_TOKEN: SecretPattern = {
  secretType: "HUGGINGFACE_TOKEN",
  patterns: [/hf_[A-Za-z0-9]{34}/g],
};

export const REPLICATE_TOKEN: SecretPattern = {
  secretType: "REPLICATE_TOKEN",
  patterns: [
    /r8_[A-Za-z0-9]{37}/g,
    /(?:REPLICATE_API_TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_-]{40})["']?/g,
  ],
};

export const GOOGLE_AI_KEY: SecretPattern = {
  secretType: "GOOGLE_AI_KEY",
  patterns: [/(?:GOOGLE_AI_KEY|GEMINI_API_KEY)\s*[:=]\s*["']?(AIza[A-Za-z0-9_-]{35})["']?/g],
};

export const MISTRAL_KEY: SecretPattern = {
  secretType: "MISTRAL_KEY",
  patterns: [/(?:MISTRAL_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?/g],
};

export const PINECONE_KEY: SecretPattern = {
  secretType: "PINECONE_KEY",
  patterns: [/(?:PINECONE_API_KEY)\s*[:=]\s*["']?([a-f0-9-]{36})["']?/g],
};

export const WEAVIATE_KEY: SecretPattern = {
  secretType: "WEAVIATE_KEY",
  patterns: [/(?:WEAVIATE_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9]{40,})["']?/g],
  minEntropy: 3.5,
};

export const WANDB_KEY: SecretPattern = {
  secretType: "WANDB_KEY",
  patterns: [/(?:WANDB_API_KEY)\s*[:=]\s*["']?([a-f0-9]{40})["']?/g],
};

export const DEEPSEEK_KEY: SecretPattern = {
  secretType: "DEEPSEEK_KEY",
  patterns: [/(?:DEEPSEEK_API_KEY)\s*[:=]\s*["']?([A-Za-z0-9_-]{40,})["']?/g],
  minEntropy: 3.5,
};

export const GROQ_KEY: SecretPattern = {
  secretType: "GROQ_KEY",
  patterns: [/gsk_[A-Za-z0-9]{52}/g],
};

export const AI_ML_PATTERNS: SecretPattern[] = [
  OPENAI_KEY,
  ANTHROPIC_KEY,
  COHERE_KEY,
  HUGGINGFACE_TOKEN,
  REPLICATE_TOKEN,
  GOOGLE_AI_KEY,
  MISTRAL_KEY,
  PINECONE_KEY,
  WEAVIATE_KEY,
  WANDB_KEY,
  DEEPSEEK_KEY,
  GROQ_KEY,
];
