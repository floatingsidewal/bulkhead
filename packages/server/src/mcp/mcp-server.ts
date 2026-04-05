import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { GuardrailsEngine, GuardResult, Detection } from "@bulkhead/core";

/** Build a human-readable summary of detections with cascade layer info */
function formatDetectionSummary(
  results: GuardResult[],
  mode: string
): string {
  const allDetections = results.flatMap((r) => r.detections);
  const lines: string[] = [];

  if (allDetections.length === 0) {
    lines.push("No issues detected.");
  } else {
    lines.push(`Found ${allDetections.length} detection${allDetections.length === 1 ? "" : "s"}:`);
    for (const d of allDetections) {
      lines.push(`  ${d.entityType} (${d.source} → ${d.disposition}, ${d.score.toFixed(2)})`);
    }
  }

  // Layer activity summary
  lines.push("");
  lines.push(formatLayerSummary(allDetections, mode));

  return lines.join("\n");
}

/** Build cascade layer activity breakdown */
function formatLayerSummary(detections: Detection[], mode: string): string {
  if (mode === "fast") {
    const confirmed = detections.filter((d) => d.source === "regex").length;
    return `Cascade: regex only (${confirmed} detected) — use mode: deep for full cascade`;
  }

  const bySource: Record<string, Detection[]> = {};
  for (const d of detections) {
    (bySource[d.source] ??= []).push(d);
  }

  const parts: string[] = [];

  const regex = bySource["regex"] ?? [];
  if (regex.length > 0 || mode !== "deep") {
    parts.push(`Layer 1 (regex): ${regex.length} confirmed`);
  }

  if (mode === "model" || mode === "deep") {
    const bert = bySource["bert"] ?? [];
    const bertConfirmed = bert.filter((d) => d.disposition === "confirmed").length;
    const bertEscalated = bert.filter((d) => d.disposition === "escalate").length;
    const bertParts = [`${bertConfirmed} confirmed`];
    if (bertEscalated > 0) bertParts.push(`${bertEscalated} escalated`);
    parts.push(`Layer 2 (BERT): ${bertParts.join(" + ")}`);
  }

  if (mode === "deep") {
    const llm = bySource["llm"] ?? [];
    const llmConfirmed = llm.filter((d) => d.disposition === "confirmed").length;
    const llmDismissed = llm.filter((d) => d.disposition === "dismissed").length;
    const llmParts: string[] = [];
    if (llmConfirmed > 0) llmParts.push(`${llmConfirmed} confirmed`);
    if (llmDismissed > 0) llmParts.push(`${llmDismissed} dismissed`);
    parts.push(`Layer 3 (LLM): ${llmParts.length > 0 ? llmParts.join(" + ") : "no escalations"}`);
  }

  return `Cascade: ${parts.join(" → ")}`;
}

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
      const summary = formatDetectionSummary(results, mode);

      return {
        content: [
          {
            type: "text" as const,
            text: summary,
          },
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
      const summary = formatDetectionSummary(results, "fast");

      return {
        content: [
          {
            type: "text" as const,
            text: summary,
          },
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
