import { describe, it, expect } from "vitest";
import { SecretGuard } from "../../src/guards/secret.guard";

describe("SecretGuard", () => {
  const guard = new SecretGuard();

  it("detects AWS access key", async () => {
    const result = await guard.analyze("Key: AKIAIOSFODNN7EXAMPLE");
    expect(result.passed).toBe(false);
    expect(result.detections.some((d) => d.entityType === "AWS_ACCESS_KEY")).toBe(true);
  });

  it("detects GitHub PAT", async () => {
    const result = await guard.analyze("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
    expect(result.passed).toBe(false);
    expect(result.detections.some((d) => d.entityType === "GITHUB_TOKEN")).toBe(true);
  });

  it("detects private key header", async () => {
    const result = await guard.analyze("-----BEGIN RSA PRIVATE KEY-----");
    expect(result.passed).toBe(false);
    expect(result.detections.some((d) => d.entityType === "PRIVATE_KEY")).toBe(true);
  });

  it("detects JWT token", async () => {
    const result = await guard.analyze(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    );
    expect(result.passed).toBe(false);
    expect(result.detections.some((d) => d.entityType === "JWT_TOKEN")).toBe(true);
  });

  it("detects database connection string", async () => {
    const result = await guard.analyze("DB_URL=postgres://user:pass@host:5432/db");
    expect(result.passed).toBe(false);
    expect(result.detections.some((d) => d.entityType === "DATABASE_CONNECTION_STRING")).toBe(true);
  });

  it("passes clean text", async () => {
    const result = await guard.analyze("Hello, this is a normal message.");
    expect(result.passed).toBe(true);
  });

  it("redacts secrets in redact mode", async () => {
    const result = await guard.analyze("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", {
      mode: "redact",
    });
    expect(result.redactedText).toContain("[REDACTED-GITHUB_TOKEN]");
  });

  it("does not flag plain GUIDs as Heroku keys", async () => {
    const result = await guard.analyze(
      "incidentid: 6658fac6-8c36-f111-88b4-70a8a53ef15d"
    );
    const heroku = result.detections.filter((d) => d.entityType === "HEROKU_API_KEY");
    expect(heroku).toHaveLength(0);
  });

  it("detects Heroku key with HEROKU_API_KEY= context", async () => {
    const result = await guard.analyze(
      "HEROKU_API_KEY=abcd1234-5678-9abc-def0-123456789abc"
    );
    expect(result.detections.some((d) => d.entityType === "HEROKU_API_KEY")).toBe(true);
  });

  describe("context-word scoring", () => {
    it("boosts score when context words are present", async () => {
      // This tests the context-word infrastructure on SecretGuard.
      // Patterns with contextWords + low baseScore will score higher when context matches.
      // Currently no built-in patterns use contextWords yet, but the mechanism is ready.
      const result = await guard.analyze("HEROKU_API_KEY=abcd1234-5678-9abc-def0-123456789abc");
      const detection = result.detections.find((d) => d.entityType === "HEROKU_API_KEY");
      expect(detection).toBeDefined();
      // Without contextWords on the pattern, score remains at default 0.9
      expect(detection!.score).toBe(0.9);
    });

    it("respects threshold with context scoring", async () => {
      const result = await guard.analyze("AKIAIOSFODNN7EXAMPLE", {
        threshold: 0.95,
      });
      // AWS key has no contextWords, so score stays at 0.9, below 0.95 threshold
      expect(result.detections.filter((d) => d.entityType === "AWS_ACCESS_KEY")).toHaveLength(0);
    });
  });
});
