/**
 * Server throughput benchmark — measures request/sec and latency distribution.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createEngine } from "@bulkhead/core";
import { createServer } from "../src/server";
import type { FastifyInstance } from "fastify";

const ITERATIONS = 200;

describe("Server Throughput Benchmarks", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    const engine = createEngine();
    app = createServer(engine, {
      port: 0,
      host: "127.0.0.1",
      logLevel: "silent",
      corsOrigin: false,
      maxBodySize: 1_048_576,
      apiKey: "",
      llmProvider: "none",
      llmApiKey: "",
      llmEndpoint: "",
      llmTimeout: 10_000,
    });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it(`/v1/scan throughput (${ITERATIONS} requests)`, async () => {
    const latencies: number[] = [];
    const body = JSON.stringify({
      text: "My SSN is 219-09-9999 and email is test@example.com. AWS key: AKIAIOSFODNN7EXAMPLE",
    });

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const response = await app.inject({
        method: "POST",
        url: "/v1/scan",
        headers: { "content-type": "application/json" },
        body,
      });
      latencies.push(performance.now() - start);
      expect(response.statusCode).toBe(200);
    }

    latencies.sort((a, b) => a - b);
    const totalMs = latencies.reduce((a, b) => a + b, 0);
    const rps = (ITERATIONS / totalMs) * 1000;

    console.log("\n");
    console.log("═".repeat(60));
    console.log("  SERVER THROUGHPUT: /v1/scan (regex only)");
    console.log("═".repeat(60));
    console.log(`  Requests:     ${ITERATIONS}`);
    console.log(`  Total time:   ${totalMs.toFixed(0)}ms`);
    console.log(`  Throughput:   ${rps.toFixed(0)} req/s`);
    console.log(`  p50 latency:  ${percentile(latencies, 50).toFixed(3)}ms`);
    console.log(`  p95 latency:  ${percentile(latencies, 95).toFixed(3)}ms`);
    console.log(`  p99 latency:  ${percentile(latencies, 99).toFixed(3)}ms`);
    console.log(`  Min latency:  ${latencies[0].toFixed(3)}ms`);
    console.log(`  Max latency:  ${latencies[latencies.length - 1].toFixed(3)}ms`);
    console.log("═".repeat(60));
  });

  it(`/v1/redact throughput (${ITERATIONS} requests)`, async () => {
    const latencies: number[] = [];
    const body = JSON.stringify({
      text: "Contact John at john@example.com, card 4532015112830366, SSN 219-09-9999",
    });

    for (let i = 0; i < ITERATIONS; i++) {
      const start = performance.now();
      const response = await app.inject({
        method: "POST",
        url: "/v1/redact",
        headers: { "content-type": "application/json" },
        body,
      });
      latencies.push(performance.now() - start);
      expect(response.statusCode).toBe(200);
    }

    latencies.sort((a, b) => a - b);
    const totalMs = latencies.reduce((a, b) => a + b, 0);
    const rps = (ITERATIONS / totalMs) * 1000;

    console.log("\n");
    console.log("═".repeat(60));
    console.log("  SERVER THROUGHPUT: /v1/redact");
    console.log("═".repeat(60));
    console.log(`  Requests:     ${ITERATIONS}`);
    console.log(`  Total time:   ${totalMs.toFixed(0)}ms`);
    console.log(`  Throughput:   ${rps.toFixed(0)} req/s`);
    console.log(`  p50 latency:  ${percentile(latencies, 50).toFixed(3)}ms`);
    console.log(`  p95 latency:  ${percentile(latencies, 95).toFixed(3)}ms`);
    console.log(`  p99 latency:  ${percentile(latencies, 99).toFixed(3)}ms`);
    console.log("═".repeat(60));
  });
});

function percentile(sorted: number[], p: number): number {
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, idx)];
}
