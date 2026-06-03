import { describe, it, expect } from "vitest";
import { createEngine, resolvePolicy } from "../../src/index";
import type { PolicyDefinition } from "../../src/policy/types";

function getDefaults() {
  return {
    enabled: true,
    debounceMs: 500,
    guards: {
      pii: { enabled: true },
      secret: { enabled: true },
      injection: { enabled: true },
      contentSafety: { enabled: false },
    },
    cascade: {
      escalationThreshold: 0.75,
      contextSentences: 3,
      modelEnabled: false,
      modelId: "Xenova/bert-base-NER",
    },
  };
}

describe("excludeEntities", () => {
  describe("policy resolution", () => {
    it("preserves excludeEntities from base policy", () => {
      const base: PolicyDefinition = {
        name: "base",
        description: "test",
        guards: {
          pii: {
            enabled: true,
            excludeEntities: ["GUID", "DATE_TIME"],
          },
        },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };

      const resolved = resolvePolicy(base);
      expect(resolved.guards.pii?.excludeEntities).toEqual(["GUID", "DATE_TIME"]);
    });

    it("unions excludeEntities from base and overlay", () => {
      const base: PolicyDefinition = {
        name: "base",
        description: "test",
        guards: {
          pii: {
            enabled: true,
            excludeEntities: ["GUID"],
          },
        },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };

      const overlay: PolicyDefinition = {
        name: "overlay",
        description: "test",
        guards: {
          pii: {
            excludeEntities: ["DATE_TIME", "IP_ADDRESS"],
          },
        },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };

      const resolved = resolvePolicy(base, overlay);
      const excluded = resolved.guards.pii?.excludeEntities;
      expect(excluded).toContain("GUID");
      expect(excluded).toContain("DATE_TIME");
      expect(excluded).toContain("IP_ADDRESS");
      expect(excluded).toHaveLength(3);
    });

    it("deduplicates when both base and overlay exclude the same entity", () => {
      const base: PolicyDefinition = {
        name: "base",
        description: "test",
        guards: {
          pii: {
            enabled: true,
            excludeEntities: ["GUID", "DATE_TIME"],
          },
        },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };

      const overlay: PolicyDefinition = {
        name: "overlay",
        description: "test",
        guards: {
          pii: {
            excludeEntities: ["GUID", "IP_ADDRESS"],
          },
        },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };

      const resolved = resolvePolicy(base, overlay);
      const excluded = resolved.guards.pii?.excludeEntities;
      expect(excluded).toHaveLength(3);
      expect(new Set(excluded)).toEqual(new Set(["GUID", "DATE_TIME", "IP_ADDRESS"]));
    });

    it("no excludeEntities when neither base nor overlay specifies it", () => {
      const base: PolicyDefinition = {
        name: "base",
        description: "test",
        guards: {
          pii: { enabled: true, threshold: 0.5 },
        },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };

      const resolved = resolvePolicy(base);
      expect(resolved.guards.pii?.excludeEntities).toBeUndefined();
    });
  });

  describe("engine scan behavior", () => {
    it("does not redact excluded entity types", async () => {
      const engine = createEngine({
        ...getDefaults(),
        policy: {
          name: "test-exclude",
          description: "test",
          guards: {
            pii: {
              enabled: true,
              threshold: 0.3,
              mode: "redact",
              excludeEntities: ["IP_ADDRESS"],
            },
          },
          riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
        },
      });

      const input = "Contact us at test@example.com or 192.168.1.100";
      const { redactedText } = await engine.scan(input);

      // Email should be redacted
      expect(redactedText).not.toContain("test@example.com");
      // IP should be preserved (excluded)
      expect(redactedText).toContain("192.168.1.100");
    });

    it("still detects excluded entities in results", async () => {
      const engine = createEngine({
        ...getDefaults(),
        policy: {
          name: "test-exclude",
          description: "test",
          guards: {
            pii: {
              enabled: true,
              threshold: 0.3,
              mode: "redact",
              excludeEntities: ["IP_ADDRESS"],
            },
          },
          riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
        },
      });

      const input = "Server at 10.0.0.1 contacted by admin@corp.com";
      const { redactedText, redactionMap, results } = await engine.scan(input);

      // IP should still be detected in guard results
      const allDetections = results.flatMap((r) => r.detections);
      const ipDetection = allDetections.find(
        (d) => d.entityType === "IP_ADDRESS"
      );
      expect(ipDetection).toBeDefined();
      expect(ipDetection?.text).toBe("10.0.0.1");

      // But IP should NOT be in redactionMap
      const ipInRedactions = Object.values(redactionMap ?? {}).some(
        (r) => (r as any).entityType === "IP_ADDRESS"
      );
      expect(ipInRedactions).toBe(false);

      // IP preserved in output text
      expect(redactedText).toContain("10.0.0.1");
    });

    it("redacts non-excluded entities normally", async () => {
      const engine = createEngine({
        ...getDefaults(),
        policy: {
          name: "test-exclude",
          description: "test",
          guards: {
            pii: {
              enabled: true,
              threshold: 0.3,
              mode: "redact",
              excludeEntities: ["GUID"],
            },
          },
          riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
        },
      });

      const input = "Email: user@domain.org, ID: 550e8400-e29b-41d4-a716-446655440000";
      const { redactedText } = await engine.scan(input);

      // Email should be redacted
      expect(redactedText).not.toContain("user@domain.org");
      // GUID should be preserved
      expect(redactedText).toContain("550e8400-e29b-41d4-a716-446655440000");
    });

    it("empty excludeEntities has no effect on behavior", async () => {
      const engine = createEngine({
        ...getDefaults(),
        policy: {
          name: "test-no-exclude",
          description: "test",
          guards: {
            pii: {
              enabled: true,
              threshold: 0.3,
              mode: "redact",
              excludeEntities: [],
            },
          },
          riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
        },
      });

      const input = "Contact: admin@example.com from 192.168.0.1";
      const { redactedText } = await engine.scan(input);

      // Both should be redacted when no exclusions
      expect(redactedText).not.toContain("admin@example.com");
      expect(redactedText).not.toContain("192.168.0.1");
    });

    it("works with multiple excluded entity types", async () => {
      const engine = createEngine({
        ...getDefaults(),
        policy: {
          name: "test-multi-exclude",
          description: "test",
          guards: {
            pii: {
              enabled: true,
              threshold: 0.3,
              mode: "redact",
              excludeEntities: ["IP_ADDRESS", "GUID"],
            },
          },
          riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
        },
      });

      const input =
        "Server 10.0.0.5, resource 550e8400-e29b-41d4-a716-446655440000, contact ops@corp.io";
      const { redactedText } = await engine.scan(input);

      // IP and GUID preserved
      expect(redactedText).toContain("10.0.0.5");
      expect(redactedText).toContain("550e8400-e29b-41d4-a716-446655440000");
      // Email redacted
      expect(redactedText).not.toContain("ops@corp.io");
    });
  });

  describe("scanObject with excludeEntities", () => {
    it("preserves excluded entities across object fields", async () => {
      const engine = createEngine({
        ...getDefaults(),
        policy: {
          name: "test-object-exclude",
          description: "test",
          guards: {
            pii: {
              enabled: true,
              threshold: 0.3,
              mode: "redact",
              excludeEntities: ["IP_ADDRESS"],
            },
          },
          riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
        },
      });

      const input = {
        title: "Server 10.0.0.1 alert",
        contact: "admin@example.com",
        notes: "Issue on 172.16.0.50 reported by support@corp.org",
      };

      const result = await engine.scanObject(input);

      // IPs preserved
      expect(result.redactedObject.title).toContain("10.0.0.1");
      expect(result.redactedObject.notes).toContain("172.16.0.50");
      // Emails redacted
      expect(result.redactedObject.contact).not.toContain("admin@example.com");
      expect(result.redactedObject.notes).not.toContain("support@corp.org");
    });
  });
});
