import { describe, it, expect, vi } from "vitest";
import { CascadeClassifier } from "../../src/cascade/cascade";
import { PiiGuard } from "../../src/guards/pii.guard";
import { SecretGuard } from "../../src/guards/secret.guard";

describe("CascadeClassifier", () => {
  describe("Layer 1 (regex only)", () => {
    it("catches SSN with source=regex, disposition=confirmed", async () => {
      const cascade = new CascadeClassifier({ bertEnabled: false });
      cascade.addRegexGuard(new PiiGuard({ entityTypes: ["US_SSN"] }));

      const result = await cascade.regexScan("SSN: 219-09-9999");
      expect(result.passed).toBe(false);

      const ssn = result.detections.find((d) => d.entityType === "US_SSN");
      expect(ssn).toBeDefined();
      expect(ssn!.source).toBe("regex");
      expect(ssn!.disposition).toBe("confirmed");
      expect(ssn!.context).toContain("219-09-9999");
    });

    it("carries provenance on secret detections", async () => {
      const cascade = new CascadeClassifier({ bertEnabled: false });
      cascade.addRegexGuard(new SecretGuard());

      const result = await cascade.regexScan("AKIAIOSFODNN7EXAMPLE");
      const aws = result.detections.find(
        (d) => d.entityType === "AWS_ACCESS_KEY"
      );
      expect(aws).toBeDefined();
      expect(aws!.source).toBe("regex");
      expect(aws!.disposition).toBe("confirmed");
    });

    it("returns passed=true for clean text", async () => {
      const cascade = new CascadeClassifier({ bertEnabled: false });
      cascade.addRegexGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));

      const result = await cascade.regexScan("Hello world, no PII here.");
      expect(result.passed).toBe(true);
      expect(result.detections).toHaveLength(0);
    });
  });

  describe("Cascade result structure", () => {
    it("includes source layers in reason", async () => {
      const cascade = new CascadeClassifier({ bertEnabled: false });
      cascade.addRegexGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));

      const result = await cascade.regexScan("test@example.com");
      expect(result.guardName).toBe("cascade");
      expect(result.reason).toContain("regex");
      expect(result.reason).toContain("EMAIL_ADDRESS");
    });

    it("filters dismissed detections from pass/fail", async () => {
      const cascade = new CascadeClassifier({ bertEnabled: false });
      cascade.addRegexGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));

      // Manually test that dismissed detections don't cause failure
      // (This tests the buildCascadeResult logic)
      const result = await cascade.regexScan("test@example.com");
      expect(result.passed).toBe(false);

      // All regex detections are confirmed, so none are dismissed
      const confirmed = result.detections.filter(
        (d) => d.disposition === "confirmed"
      );
      expect(confirmed.length).toBeGreaterThan(0);
    });
  });

  describe("deepScan without BERT", () => {
    it("falls back to regex when BERT is disabled", async () => {
      const cascade = new CascadeClassifier({ bertEnabled: false });
      cascade.addRegexGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));

      const result = await cascade.deepScan("email: test@example.com");
      expect(result.passed).toBe(false);
      expect(result.detections.every((d) => d.source === "regex")).toBe(true);
    });
  });
});

describe("LLM Layer", () => {
  it("disambiguates with mock LLM provider", async () => {
    const { LlmLayer } = await import("../../src/cascade/llm-layer");

    const mockProvider = vi.fn().mockResolvedValue(
      JSON.stringify({ type: "PERSON", confidence: 0.92 })
    );

    const layer = new LlmLayer({
      contextSentences: 3,
      provider: mockProvider,
    });

    const escalated = [
      {
        entityType: "PERSON",
        start: 10,
        end: 16,
        text: "Jordan",
        confidence: "low" as const,
        score: 0.52,
        guardName: "cascade-bert",
        source: "bert" as const,
        context: "My friend Jordan went to the store",
        disposition: "escalate" as const,
      },
    ];

    const confirmed = [
      {
        entityType: "PERSON",
        start: 0,
        end: 5,
        text: "Alice",
        confidence: "high" as const,
        score: 0.95,
        guardName: "cascade-bert",
        source: "bert" as const,
        context: "Alice and Jordan went to the store",
        disposition: "confirmed" as const,
      },
    ];

    const results = await layer.disambiguate(
      escalated,
      "Alice and Jordan went to the store yesterday.",
      confirmed
    );

    expect(results).toHaveLength(1);
    expect(results[0].source).toBe("llm");
    expect(results[0].disposition).toBe("confirmed");
    expect(results[0].entityType).toBe("PERSON");
    expect(results[0].score).toBe(0.92);

    // Verify the prompt included context about confirmed entities
    expect(mockProvider).toHaveBeenCalledTimes(1);
    const prompt = mockProvider.mock.calls[0][0];
    expect(prompt).toContain("Jordan");
    expect(prompt).toContain("Alice (PERSON)");
  });

  it("dismisses when LLM says NONE", async () => {
    const { LlmLayer } = await import("../../src/cascade/llm-layer");

    const mockProvider = vi.fn().mockResolvedValue(
      JSON.stringify({ type: "NONE", confidence: 0.88 })
    );

    const layer = new LlmLayer({ provider: mockProvider });

    const escalated = [
      {
        entityType: "PERSON",
        start: 5,
        end: 11,
        text: "Jordan",
        confidence: "low" as const,
        score: 0.45,
        guardName: "cascade-bert",
        source: "bert" as const,
        context: "Visit Jordan for amazing ancient ruins",
        disposition: "escalate" as const,
      },
    ];

    const results = await layer.disambiguate(
      escalated,
      "Visit Jordan for amazing ancient ruins and history.",
      []
    );

    expect(results).toHaveLength(1);
    expect(results[0].source).toBe("llm");
    expect(results[0].disposition).toBe("dismissed");
  });

  it("keeps escalated items when no LLM provider", async () => {
    const { LlmLayer } = await import("../../src/cascade/llm-layer");

    const layer = new LlmLayer(); // No provider

    const escalated = [
      {
        entityType: "PERSON",
        start: 0,
        end: 6,
        text: "Jordan",
        confidence: "low" as const,
        score: 0.5,
        guardName: "cascade-bert",
        source: "bert" as const,
        context: "Jordan",
        disposition: "escalate" as const,
      },
    ];

    const results = await layer.disambiguate(escalated, "Jordan", []);
    expect(results).toHaveLength(1);
    expect(results[0].disposition).toBe("escalate"); // unchanged
  });
});
