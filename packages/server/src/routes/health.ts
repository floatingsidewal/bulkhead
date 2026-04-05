import type { FastifyInstance } from "fastify";
import type { GuardrailsEngine } from "@bulkhead/core";

export function registerHealthRoutes(app: FastifyInstance, engine: GuardrailsEngine): void {
  // Liveness probe — always returns 200 if the process is running
  app.get("/healthz", async (_request, reply) => {
    return reply.send({ status: "ok" });
  });

  // Readiness probe — checks that the engine is ready to serve
  app.get("/readyz", async (_request, reply) => {
    return reply.send({
      status: "ready",
      guards: engine.guardNames,
    });
  });

  // Info endpoint — returns version, enabled guards, cascade status
  app.get("/v1/info", async (_request, reply) => {
    return reply.send({
      name: "bulkhead",
      version: "0.1.0",
      guards: engine.guardNames,
    });
  });
}
