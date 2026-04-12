import { describe, it, expect } from "vitest";
import {
  createEngine,
  getPolicy,
  resolvePolicy,
  assessRisk,
  BUILTIN_POLICIES,
} from "../../src/index";
import type { PolicyDefinition, RiskAssessment } from "../../src/policy/types";

describe("Policy System", () => {
  describe("getPolicy", () => {
    it("retrieves strict policy", () => {
      const policy = getPolicy("strict");
      expect(policy.name).toBe("strict");
      expect(policy.guards.pii?.threshold).toBe(0.3);
      expect(policy.guards.pii?.mode).toBe("block");
    });

    it("retrieves moderate policy", () => {
      const policy = getPolicy("moderate");
      expect(policy.name).toBe("moderate");
      expect(policy.guards.pii?.threshold).toBe(0.5);
      expect(policy.guards.pii?.mode).toBe("redact");
    });

    it("throws on unknown policy", () => {
      expect(() => getPolicy("nonexistent")).toThrow("Unknown policy");
    });
  });

  describe("resolvePolicy", () => {
    it("returns base policy when no overlays", () => {
      const resolved = resolvePolicy("strict");
      expect(resolved.name).toBe("strict");
    });

    it("composes two policies with stricter-wins semantics", () => {
      const custom: PolicyDefinition = {
        name: "pci-overlay",
        description: "PCI-DSS overlay",
        guards: {
          pii: {
            enabled: true,
            threshold: 0.2,
            entityTypes: ["CREDIT_CARD", "US_BANK_NUMBER"],
          },
        },
        riskThresholds: { critical: 0.8, high: 0.6, medium: 0.4, low: 0.2 },
      };

      const resolved = resolvePolicy("moderate", custom);
      // Threshold: min(0.5, 0.2) = 0.2
      expect(resolved.guards.pii?.threshold).toBe(0.2);
      // Entity types: overlay narrows to CREDIT_CARD, US_BANK_NUMBER
      expect(resolved.guards.pii?.entityTypes).toEqual([
        "CREDIT_CARD",
        "US_BANK_NUMBER",
      ]);
      // Name reflects composition
      expect(resolved.name).toContain("+");
    });

    it("block mode wins over redact", () => {
      const overlay: PolicyDefinition = {
        name: "block-overlay",
        description: "Forces block mode",
        guards: { pii: { mode: "block" } },
        riskThresholds: { critical: 0.9, high: 0.8, medium: 0.65, low: 0.5 },
      };

      const resolved = resolvePolicy("moderate", overlay);
      expect(resolved.guards.pii?.mode).toBe("block");
    });
  });

  describe("assessRisk", () => {
    const policy = getPolicy("strict");

    it("returns none for clean text", () => {
      const assessment = assessRisk(
        [
          {
            passed: true,
            reason: "No issues",
            guardName: "pii",
            score: 0,
            detections: [],
          },
        ],
        policy
      );
      expect(assessment.level).toBe("none");
      expect(assessment.score).toBe(0);
      expect(assessment.issues).toHaveLength(0);
    });

    it("rates high-score detections as critical", () => {
      const assessment = assessRisk(
        [
          {
            passed: false,
            reason: "Detected",
            guardName: "secret",
            score: 0.95,
            detections: [
              {
                entityType: "AWS_ACCESS_KEY",
                start: 0,
                end: 20,
                text: "AKIAIOSFODNN7EXAMPLE",
                confidence: "high",
                score: 0.95,
                guardName: "secret",
                source: "regex",
                context: "AKIAIOSFODNN7EXAMPLE",
                disposition: "confirmed",
              },
            ],
          },
        ],
        policy
      );
      expect(assessment.level).toBe("critical");
      expect(assessment.issues).toHaveLength(1);
      expect(assessment.issues[0].entityType).toBe("AWS_ACCESS_KEY");
      expect(assessment.issues[0].category).toBe("secret");
    });

    it("separates test data from risk scoring", () => {
      const assessment = assessRisk(
        [
          {
            passed: false,
            reason: "Detected SSN",
            guardName: "pii",
            score: 0.85,
            detections: [
              {
                entityType: "US_SSN",
                start: 5,
                end: 16,
                text: "123-45-6789",
                confidence: "high",
                score: 0.85,
                guardName: "pii",
                source: "regex",
                context: "ssn: 123-45-6789",
                disposition: "confirmed",
              },
            ],
          },
          {
            passed: true,
            reason: "Test data",
            guardName: "testdata",
            score: 0.95,
            detections: [
              {
                entityType: "TEST_DATA_SSN",
                start: 5,
                end: 16,
                text: "123-45-6789",
                confidence: "high",
                score: 0.95,
                guardName: "testdata",
                source: "regex",
                context: "ssn: 123-45-6789",
                disposition: "informational",
              },
            ],
          },
        ],
        policy
      );

      // Risk score based on real detections only
      expect(assessment.score).toBe(0.85);
      // Test data flags present
      expect(assessment.testDataFlags).toHaveLength(1);
      // Issue is annotated as test data (overlapping)
      expect(assessment.issues).toHaveLength(1);
      expect(assessment.issues[0].isTestData).toBe(true);
    });
  });

  describe("createEngine with policy", () => {
    it("creates engine with strict policy", async () => {
      const engine = createEngine({ ...getDefaults(), policy: "strict" });
      expect(engine.guardNames).toContain("pii");
      expect(engine.guardNames).toContain("secret");
      expect(engine.guardNames).toContain("injection");
      expect(engine.guardNames).toContain("leakage");
      expect(engine.guardNames).toContain("testdata");
    });

    it("creates engine with testdata detection disabled", async () => {
      const policy: PolicyDefinition = {
        ...getPolicy("moderate"),
        testDataDetection: "ignore",
      };
      const engine = createEngine({ ...getDefaults(), policy });
      expect(engine.guardNames).not.toContain("testdata");
    });

    it("backwards compatible without policy", async () => {
      const engine = createEngine();
      expect(engine.guardNames).toContain("pii");
      expect(engine.guardNames).toContain("secret");
      // No testdata guard without policy
      expect(engine.guardNames).not.toContain("testdata");
    });
  });

  describe("policyScan", () => {
    it("returns risk assessment for support ticket data", async () => {
      const engine = createEngine({ ...getDefaults(), policy: "strict" });
      const policy = getPolicy("strict");

      const ticketFragment = `
        "_primarycontactid_value": "00000000-eval-0001-0000-000000000001",
        "ticketnumber": "2604120030000099",
        "msdfm_modifiedbyuserinitiating": "Upn:SxG-Email-PROD_2091ca3b-4ab0-448b-a116-3adc8a4f2f9e@6a25e557-3464-4468-abaa-94794b5f8437.com",
        "customerStatement": "I am a B.Tech student in India and I'm facing a billing issue. My SSN is 123-45-6789."
      `;

      const { risk, results } = await engine.policyScan(ticketFragment, policy);

      // Should have risk assessment
      expect(risk.level).toBeDefined();
      expect(risk.issues.length).toBeGreaterThan(0);
      // Should have test data flags for the eval GUID
      expect(risk.testDataFlags.length).toBeGreaterThan(0);
      // Results should include both real guards and testdata guard
      const guardNames = results.map((r) => r.guardName);
      expect(guardNames).toContain("testdata");
    });
  });
});

/** Helper to get default config with minimal properties for testing */
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
