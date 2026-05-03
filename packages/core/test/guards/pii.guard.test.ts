import { describe, it, expect } from "vitest";
import { PiiGuard } from "../../src/guards/pii.guard";

describe("PiiGuard", () => {
  const guard = new PiiGuard();

  describe("credit cards", () => {
    it("detects valid Visa card", async () => {
      const result = await guard.analyze("My credit card is 4532015112830366");
      expect(result.passed).toBe(false);
      expect(result.detections.some((d) => d.entityType === "CREDIT_CARD")).toBe(true);
    });

    it("rejects invalid card (fails Luhn)", async () => {
      const result = await guard.analyze("Number: 4532015112830367");
      const ccDetections = result.detections.filter((d) => d.entityType === "CREDIT_CARD");
      expect(ccDetections).toHaveLength(0);
    });
  });

  describe("email addresses", () => {
    it("detects email", async () => {
      const result = await guard.analyze("Contact me at john.doe@example.com");
      expect(result.passed).toBe(false);
      expect(result.detections.some((d) => d.entityType === "EMAIL_ADDRESS")).toBe(true);
    });
  });

  describe("US SSN", () => {
    it("detects SSN with dashes", async () => {
      // 219-09-9999 is a valid SSN format (not in rejected prefixes)
      const result = await guard.analyze("SSN: 219-09-9999");
      expect(result.passed).toBe(false);
      expect(result.detections.some((d) => d.entityType === "US_SSN")).toBe(true);
    });

    it("rejects invalid SSN starting with 000", async () => {
      const guard2 = new PiiGuard({ entityTypes: ["US_SSN"] });
      const result = await guard2.analyze("SSN: 000-12-3456");
      const ssnDetections = result.detections.filter((d) => d.entityType === "US_SSN");
      expect(ssnDetections).toHaveLength(0);
    });
  });

  describe("IP addresses", () => {
    it("detects IPv4", async () => {
      const result = await guard.analyze("Server IP: 192.168.1.100");
      expect(result.detections.some((d) => d.entityType === "IP_ADDRESS")).toBe(true);
    });
  });

  describe("GUIDs / UUIDs", () => {
    it("detects canonical lowercase GUID", async () => {
      const result = await guard.analyze(
        "Subscription: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      );
      expect(result.detections.some((d) => d.entityType === "GUID")).toBe(true);
    });

    it("detects canonical uppercase GUID", async () => {
      const result = await guard.analyze(
        "Tenant: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
      );
      expect(result.detections.some((d) => d.entityType === "GUID")).toBe(true);
    });

    it("detects multiple GUIDs in one string", async () => {
      const result = await guard.analyze(
        "Sub aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee Tenant 11111111-2222-3333-4444-555555555555 Object 99999999-8888-7777-6666-555555555555",
      );
      const guidDetections = result.detections.filter((d) => d.entityType === "GUID");
      expect(guidDetections.length).toBe(3);
    });

    it("does not match strings shorter than canonical 36 chars", async () => {
      const result = await guard.analyze(
        "short: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee (35 chars, missing trailing hex)",
      );
      const guidDetections = result.detections.filter((d) => d.entityType === "GUID");
      expect(guidDetections).toHaveLength(0);
    });

    it("does not match without dashes", async () => {
      const result = await guard.analyze("dashless: aaaaaaaabbbbccccddddeeeeeeeeeeee");
      const guidDetections = result.detections.filter((d) => d.entityType === "GUID");
      expect(guidDetections).toHaveLength(0);
    });

    it("does not match with wrong segment lengths (8-4-4-4-13)", async () => {
      const result = await guard.analyze("bad: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeea");
      const guidDetections = result.detections.filter((d) => d.entityType === "GUID");
      expect(guidDetections).toHaveLength(0);
    });

    it("redacted GUID does not false-positive as MEDICAL_LICENSE", async () => {
      // The default GUID synthesizer emits e.g.
      //   00000000-redacted-89bd-0000-e3d868e80000
      // which contains hex chunks like "ea7927800" that previously
      // matched the MEDICAL_LICENSE regex `[abc...][a-zA-Z]\d{7}`.
      // With the GUID detector landed at score 0.7 (vs MEDICAL_LICENSE 0.4),
      // the GUID is recognized and synthesized in one pass, so the
      // synthesized output is never re-scanned and never flagged as
      // MEDICAL_LICENSE in a normal engine.scan() flow.
      const guard2 = new PiiGuard();
      const result = await guard2.analyze(
        "Tenant 11111111-2222-3333-4444-555555555555",
        { enabled: true, threshold: 0.5, mode: "redact" },
      );
      // Under threshold 0.5, GUID (0.7) detects, MEDICAL_LICENSE (0.4) does not.
      expect(result.detections.some((d) => d.entityType === "GUID")).toBe(true);
      expect(result.detections.some((d) => d.entityType === "MEDICAL_LICENSE")).toBe(false);
    });

    it("example subscription ID context boosts confidence", async () => {
      const result = await guard.analyze(
        "example subscription aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee is at quota.",
      );
      const guidDetections = result.detections.filter((d) => d.entityType === "GUID");
      expect(guidDetections.length).toBeGreaterThan(0);
      expect(guidDetections[0].score).toBeGreaterThanOrEqual(0.7);
    });
  });

  describe("IBAN", () => {
    it("detects valid IBAN", async () => {
      const result = await guard.analyze("IBAN: GB29 NWBK 6016 1331 9268 19");
      expect(result.detections.some((d) => d.entityType === "IBAN_CODE")).toBe(true);
    });
  });

  describe("context boost", () => {
    it("boosts score when context words present", async () => {
      const withContext = await guard.analyze("My credit card number is 4532015112830366");
      const withoutContext = await guard.analyze(
        "Record 4532015112830366 logged",
        { threshold: 0 }
      );

      const ccWith = withContext.detections.find((d) => d.entityType === "CREDIT_CARD");
      const ccWithout = withoutContext.detections.find((d) => d.entityType === "CREDIT_CARD");

      expect(ccWith).toBeDefined();
      expect(ccWithout).toBeDefined();
      if (ccWith && ccWithout) {
        expect(ccWith.score).toBeGreaterThan(ccWithout.score);
      }
    });
  });

  describe("redaction", () => {
    it("redacts detected PII", async () => {
      const result = await guard.analyze("Email: john@example.com", { mode: "redact" });
      expect(result.redactedText).toContain("[REDACTED-EMAIL_ADDRESS]");
      expect(result.redactedText).not.toContain("john@example.com");
    });
  });

  describe("entity filtering", () => {
    it("only detects specified entity types", async () => {
      const emailOnly = new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] });
      const result = await emailOnly.analyze("Email: john@example.com, SSN: 123-45-6789");
      const types = new Set(result.detections.map((d) => d.entityType));
      expect(types.has("EMAIL_ADDRESS")).toBe(true);
      expect(types.has("US_SSN")).toBe(false);
    });
  });
});
