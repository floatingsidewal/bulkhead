import { describe, expect, it } from "vitest";
import { sanitizeDocument } from "../../src";
import type { PolicyDefinition } from "../../src/policy/types";
import type { JsonValue } from "../../src/types";
import { arbitrateDetections } from "../../src/sanitization/arbitration";
import type { CollectedDetection, StringLocation } from "../../src/sanitization/types";

const policy: PolicyDefinition = {
  name: "property", description: "synthetic", guards: { pii: { enabled: true, threshold: 0.2, mode: "redact" } },
  riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.2 }, testDataDetection: "ignore",
};

describe("sanitizeDocument invariants", () => {
  it("creates non-overlapping deterministic plans for generated mutation spans", () => {
    const location: StringLocation = { id: "0", path: "$.value", kind: "value", text: "x".repeat(80) };
    for (let seed = 1; seed <= 40; seed++) {
      const detections: CollectedDetection[] = Array.from({ length: 8 }, (_, index) => {
        const start = (seed * 13 + index * 17) % 60;
        const end = Math.min(80, start + 1 + ((seed + index * 7) % 20));
        return {
          location,
          detection: {
            entityType: `TYPE_${index % 3}`, start, end, text: location.text.slice(start, end),
            confidence: index % 2 ? "medium" : "high", score: 0.5 + index / 100,
            guardName: index % 3 ? "pii" : "secret", source: "regex",
            context: location.text, disposition: "confirmed",
          },
        };
      });
      const first = arbitrateDetections(detections);
      expect(arbitrateDetections([...detections].reverse())).toEqual(first);
      for (let index = 1; index < first.length; index++) {
        expect(first[index - 1].end).toBeLessThanOrEqual(first[index].start);
      }
    }
  });

  it("keeps generated nested JSON documents immutable, shape-preserving, and round-trippable", async () => {
    const leaves: JsonValue[] = ["safe", "user@example.com", "2026-02-31", "\\quoted\\", 42, true, null];
    const generate = (seed: number, depth: number): JsonValue => {
      const next = (salt: number) => (seed * 1103515245 + salt * 12345 + 12345) >>> 0;
      if (depth === 0) return leaves[next(depth) % leaves.length];
      switch (next(depth) % 3) {
        case 0:
          return [generate(next(1), depth - 1), generate(next(2), depth - 1)];
        case 1:
          return {
            [`field-${next(3) % 7}`]: generate(next(4), depth - 1),
            [`email-${next(5) % 5}`]: generate(next(6), depth - 1),
          };
        default:
          return leaves[next(7) % leaves.length];
      }
    };
    const shape = (value: JsonValue): unknown => {
      if (Array.isArray(value)) return value.map(shape);
      if (value !== null && typeof value === "object") {
        return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, shape(entry)]));
      }
      return typeof value;
    };
    for (let seed = 0; seed < 40; seed++) {
      const input = generate(seed, 3);
      const before = JSON.stringify(input);
      const result = await sanitizeDocument(input, policy);
      expect(JSON.stringify(input)).toBe(before);
      expect(JSON.parse(JSON.stringify(result.value))).toEqual(result.value);
      expect(shape(result.value)).toEqual(shape(input));
      expect(result.metadata.postTreatment.structurallyValid).toBe(true);
    }
  });
});
