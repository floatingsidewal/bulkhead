import { expect, it } from "vitest";
import { sanitizeDocument } from "../../src";
import type { SanitizePolicy } from "../../src";

it("supports a minimal policy + one awaited call + fail-closed gate", async () => {
  const policy: SanitizePolicy = {
    name: "consumer-contract",
    description: "synthetic consumer contract",
    guards: { pii: { enabled: true, threshold: 0.2, mode: "redact" } },
    riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.2 },
    testDataDetection: "ignore",
  };
  const result = await sanitizeDocument({ contact: "person@example.com" }, policy);
  if (!result.metadata.postTreatment.safe || !result.metadata.postTreatment.structurallyValid) {
    throw new Error("Sanitization boundary rejected output");
  }
  expect(result.value.contact).toBe("[REDACTED-EMAIL_ADDRESS]");
});
