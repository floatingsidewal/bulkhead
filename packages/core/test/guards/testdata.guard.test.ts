import { describe, it, expect } from "vitest";
import { TestDataGuard } from "../../src/guards/testdata.guard";

describe("TestDataGuard", () => {
  const guard = new TestDataGuard();

  describe("synthetic GUIDs", () => {
    it("detects GUIDs with eval keyword", async () => {
      const result = await guard.analyze(
        "id: 00000000-eval-0005-0000-000000000001"
      );
      expect(result.passed).toBe(true); // informational, always passes
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_GUID");
      expect(result.detections[0].disposition).toBe("informational");
    });

    it("detects GUIDs with test keyword", async () => {
      const result = await guard.analyze(
        "ref: 00000000-test-0001-0000-000000000001"
      );
      expect(result.detections.length).toBeGreaterThanOrEqual(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_GUID");
    });

    it("detects zero-padded GUIDs", async () => {
      const result = await guard.analyze(
        "id: 00000000-0000-0000-0000-000000000000"
      );
      expect(result.detections.length).toBeGreaterThanOrEqual(1);
    });

    it("detects multiple eval GUIDs from support ticket", async () => {
      const text = `
        "_primarycontactid_value": "00000000-eval-0001-0000-000000000001",
        "incidentid": "00000000-eval-0002-0000-000000000001",
        "_customerid_value": "00000000-eval-0003-0000-000000000001",
      `;
      const result = await guard.analyze(text);
      expect(result.detections.length).toBeGreaterThanOrEqual(3);
      expect(
        result.detections.every((d) => d.entityType === "TEST_DATA_GUID")
      ).toBe(true);
    });
  });

  describe("test credit cards", () => {
    it("detects Visa test number", async () => {
      const result = await guard.analyze("card: 4111111111111111");
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_CREDIT_CARD");
    });

    it("detects Stripe test number", async () => {
      const result = await guard.analyze("card: 4242424242424242");
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_CREDIT_CARD");
    });
  });

  describe("test SSNs", () => {
    it("detects famous test SSN 123-45-6789", async () => {
      const result = await guard.analyze("ssn: 123-45-6789");
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_SSN");
    });

    it("detects all-zero SSN", async () => {
      const result = await guard.analyze("ssn: 000-00-0000");
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_SSN");
    });
  });

  describe("test emails", () => {
    it("detects @example.com", async () => {
      const result = await guard.analyze("email: user@example.com");
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_EMAIL");
    });

    it("detects noreply@", async () => {
      const result = await guard.analyze(
        "from: noreply@somecompany.com"
      );
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_EMAIL");
    });
  });

  describe("sequential patterns", () => {
    it("detects AAAA000000000001 PUID pattern", async () => {
      const result = await guard.analyze("puid: AAAA000000000001");
      expect(result.detections).toHaveLength(1);
      expect(result.detections[0].entityType).toBe("TEST_DATA_SEQUENTIAL");
    });
  });

  it("returns no detections for clean text", async () => {
    const result = await guard.analyze(
      "This is a normal support ticket about billing"
    );
    expect(result.detections).toHaveLength(0);
    expect(result.passed).toBe(true);
  });

  it("does not flag real GUIDs", async () => {
    const result = await guard.analyze(
      "id: a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    );
    expect(result.detections).toHaveLength(0);
  });
});
