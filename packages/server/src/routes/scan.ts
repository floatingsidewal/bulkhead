import type { FastifyInstance } from "fastify";
import type { GuardrailsEngine, EngineConfig } from "@bulkhead/core";

interface ScanBody {
  text: string;
  config?: Partial<EngineConfig>;
}

const scanBodySchema = {
  type: "object" as const,
  required: ["text"],
  properties: {
    text: { type: "string" as const },
    config: { type: "object" as const },
  },
};

export function registerScanRoutes(app: FastifyInstance, engine: GuardrailsEngine): void {
  // Layer 1 only: regex scan (sub-ms)
  app.post<{ Body: ScanBody }>("/v1/scan", {
    schema: { body: scanBodySchema },
  }, async (request, reply) => {
    const { text, config } = request.body;

    if (config) {
      engine.updateConfig(config);
    }

    const results = await engine.analyze(text);
    const passed = results.every((r) => r.passed);

    return reply.send({ passed, results });
  });

  // Full cascade: regex + BERT + LLM
  app.post<{ Body: ScanBody }>("/v1/scan/deep", {
    schema: { body: scanBodySchema },
  }, async (request, reply) => {
    const { text } = request.body;
    const results = await engine.deepScan(text);
    const passed = results.every((r) => r.passed);

    return reply.send({ passed, results });
  });

  // Regex + BERT only (no LLM)
  app.post<{ Body: ScanBody }>("/v1/scan/model", {
    schema: { body: scanBodySchema },
  }, async (request, reply) => {
    const { text } = request.body;
    const results = await engine.modelScan(text);
    const passed = results.every((r) => r.passed);

    return reply.send({ passed, results });
  });

  // Scan + return redacted text
  app.post<{ Body: ScanBody }>("/v1/redact", {
    schema: { body: scanBodySchema },
  }, async (request, reply) => {
    const { text } = request.body;
    const { passed, results, redactedText } = await engine.scan(text);

    return reply.send({ passed, results, redactedText });
  });
}
