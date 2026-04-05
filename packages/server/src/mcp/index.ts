import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createEngine } from "@bulkhead/core";
import { loadConfig } from "../config";
import { createLlmProvider } from "../llm-providers";
import { createMcpServer } from "./mcp-server";

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

  const server = createMcpServer(engine);
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Graceful shutdown
  process.on("SIGTERM", async () => {
    await engine.dispose();
    await server.close();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error("Failed to start MCP server:", err);
  process.exit(1);
});
