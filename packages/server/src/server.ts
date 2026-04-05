import Fastify, { type FastifyInstance } from "fastify";
import type { GuardrailsEngine } from "@bulkhead/core";
import type { ServerConfig } from "./config";
import { registerScanRoutes } from "./routes/scan";
import { registerHealthRoutes } from "./routes/health";

export function createServer(
  engine: GuardrailsEngine,
  config: ServerConfig
): FastifyInstance {
  const app = Fastify({
    logger: config.logLevel !== "silent"
      ? {
          level: config.logLevel,
          // SECURITY: Never log request bodies — they contain the sensitive data being scanned
          serializers: {
            req(request) {
              return {
                method: request.method,
                url: request.url,
                hostname: request.hostname,
                remoteAddress: request.ip,
              };
            },
          },
        }
      : false,
    bodyLimit: config.maxBodySize,
  });

  // CORS (disabled by default)
  if (config.corsOrigin) {
    app.addHook("onRequest", async (request, reply) => {
      reply.header("Access-Control-Allow-Origin", config.corsOrigin);
      reply.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      reply.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

      if (request.method === "OPTIONS") {
        return reply.status(204).send();
      }
    });
  }

  // Error handler
  app.setErrorHandler(async (error: Error & { validation?: unknown }, _request, reply) => {
    if ("validation" in error && error.validation) {
      return reply.status(400).send({
        error: "Bad Request",
        message: error.message,
      });
    }

    app.log.error(error);
    return reply.status(500).send({
      error: "Internal Server Error",
      message: "An unexpected error occurred",
    });
  });

  // Register routes
  registerHealthRoutes(app, engine);
  registerScanRoutes(app, engine);

  return app;
}
