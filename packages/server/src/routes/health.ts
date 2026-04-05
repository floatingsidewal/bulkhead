import type { FastifyInstance } from "fastify";
import type { GuardrailsEngine } from "@bulkhead/core";

export function registerHealthRoutes(app: FastifyInstance, engine: GuardrailsEngine): void {
  // Liveness probe — always returns 200 if the process is running
  app.get("/healthz", async (_request, reply) => {
    return reply.send({ status: "ok" });
  });

  // Readiness probe — checks that the engine and cascade are ready to serve
  app.get("/readyz", async (_request, reply) => {
    const cascadeReady = engine.cascadeReady;
    const status = cascadeReady ? "ready" : "loading";
    const code = cascadeReady ? 200 : 503;

    return reply.status(code).send({
      status,
      guards: engine.guardNames,
      cascadeReady,
    });
  });

  // Info endpoint — returns version, enabled guards, cascade status
  app.get("/v1/info", async (_request, reply) => {
    return reply.send({
      name: "bulkhead",
      version: "0.1.0",
      guards: engine.guardNames,
      cascadeReady: engine.cascadeReady,
    });
  });
}
