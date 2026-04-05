import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { GuardrailsEngine } from "@bulkhead/core";

export function createMcpServer(engine: GuardrailsEngine): McpServer {
  const server = new McpServer({
    name: "bulkhead",
    version: "0.1.0",
  });

  // Scan tool — run guards against text
  server.tool(
    "bulkhead_scan",
    "Scan text for PII, secrets, prompt injection, and system prompt leakage. Returns detections with confidence scores and entity types.",
    {
      text: z.string().describe("The text to scan for sensitive content"),
      mode: z
        .enum(["fast", "model", "deep"])
        .default("fast")
        .describe("Scan mode: 'fast' (regex only), 'model' (regex + BERT), 'deep' (full cascade with LLM)"),
    },
    async ({ text, mode }) => {
      let results;
      switch (mode) {
        case "deep":
          results = await engine.deepScan(text);
          break;
        case "model":
          results = await engine.modelScan(text);
          break;
        default:
          results = await engine.analyze(text);
      }

      const passed = results.every((r) => r.passed);
      const allDetections = results.flatMap((r) => r.detections);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                passed,
                detectionCount: allDetections.length,
                results: results.map((r) => ({
                  guardName: r.guardName,
                  passed: r.passed,
                  score: r.score,
                  detections: r.detections.map((d) => ({
                    entityType: d.entityType,
                    text: d.text,
                    confidence: d.confidence,
                    score: d.score,
                    source: d.source,
                    disposition: d.disposition,
                  })),
                })),
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // Redact tool — scan and return redacted text
  server.tool(
    "bulkhead_redact",
    "Scan text and return a redacted version with sensitive content replaced by [REDACTED-TYPE] placeholders.",
    {
      text: z.string().describe("The text to redact"),
    },
    async ({ text }) => {
      const { passed, results, redactedText } = await engine.scan(text);
      const allDetections = results.flatMap((r) => r.detections);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                passed,
                detectionCount: allDetections.length,
                redactedText: redactedText ?? text,
                detections: allDetections.map((d) => ({
                  entityType: d.entityType,
                  text: d.text,
                  confidence: d.confidence,
                })),
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // Configure tool — update guard settings at runtime
  server.tool(
    "bulkhead_configure",
    "Enable or disable specific guards at runtime. Returns the current guard configuration.",
    {
      guards: z
        .record(z.string(), z.object({ enabled: z.boolean() }))
        .optional()
        .describe("Guard configuration overrides, e.g. { \"pii\": { \"enabled\": false } }"),
    },
    async ({ guards }) => {
      if (guards) {
        engine.updateConfig({ guards });
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                status: "ok",
                activeGuards: engine.guardNames,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}
