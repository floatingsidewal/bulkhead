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
});
