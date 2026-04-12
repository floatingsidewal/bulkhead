import { createEngine } from "@bulkhead-ai/core";
import { loadConfig } from "./config";
import { createServer } from "./server";
import { createLlmProvider } from "./llm-providers";

async function main(): Promise<void> {
  const config = loadConfig();
  const engine = createEngine(config.engine);

  // Configure LLM provider if specified
  const llmProvider = createLlmProvider(config.server);
  if (llmProvider && config.engine.cascade.modelEnabled) {
    engine.initCascade({
      bertEnabled: config.engine.cascade.modelEnabled,
      llmEnabled: true,
      escalationThreshold: config.engine.cascade.escalationThreshold,
      contextSentences: config.engine.cascade.contextSentences,
      modelId: config.engine.cascade.modelId,
      llmProvider,
    });
  }

  const server = createServer(engine, config.server);

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    server.log.info(`Received ${signal}, shutting down...`);
    await server.close();
    await engine.dispose();
    process.exit(0);
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  try {
    await server.listen({
      port: config.server.port,
      host: config.server.host,
    });
    console.log(`Bulkhead server listening on ${config.server.host}:${config.server.port}`);
    console.log(`Guards: ${engine.guardNames.join(", ")}`);
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

main();
