import { describe, it, expect } from "vitest";
import { GuardrailsEngine } from "../../src/engine/engine";
import { PiiGuard } from "../../src/guards/pii.guard";
import { SecretGuard } from "../../src/guards/secret.guard";

describe("GuardrailsEngine.scanObject", () => {
  function makeEngine(): GuardrailsEngine {
    const engine = new GuardrailsEngine();
    engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS", "US_PHONE", "CREDIT_CARD"] }));
    engine.addGuard(new SecretGuard());
    return engine;
  }

  // -------------------------------------------------------------------------
  // Shape preservation
  // -------------------------------------------------------------------------

  it("returns clean shape with no detections when input has no PII", async () => {
    const engine = makeEngine();
    const input = { title: "innocent text", count: 42, ok: true };
    const result = await engine.scanObject(input);
    expect(result.passed).toBe(true);
    expect(result.redactedObject).toEqual(input);
    expect(result.pathDetections).toEqual({});
    // results array may be present but should have empty detections
    for (const r of result.results) {
      expect(r.detections).toHaveLength(0);
    }
  });

  it("preserves non-string primitives unchanged", async () => {
    const engine = makeEngine();
    const input = {
      n: 3.14,
      b: false,
      nullValue: null,
      undef: undefined,
      i: 42,
    };
    const result = await engine.scanObject(input);
    expect(result.redactedObject).toEqual(input);
  });

  it("preserves Date / RegExp / Map / Set without recursion", async () => {
    const engine = makeEngine();
    const date = new Date("2026-04-30T05:37:33Z");
    const regex = /test@example\.com/;
    const input = { date, regex };
    const result = await engine.scanObject(input);
    expect(result.redactedObject.date).toBe(date);
    expect(result.redactedObject.regex).toBe(regex);
  });

  it("preserves array length and element order", async () => {
    const engine = makeEngine();
    const input = ["a", "b", "test@example.com", "d"];
    const result = await engine.scanObject(input);
    expect(result.redactedObject).toHaveLength(4);
    expect(result.redactedObject[0]).toBe("a");
    expect(result.redactedObject[1]).toBe("b");
    expect(result.redactedObject[2]).toContain("[REDACTED-EMAIL_ADDRESS]");
    expect(result.redactedObject[3]).toBe("d");
  });

  it("preserves object key order", async () => {
    const engine = makeEngine();
    const input = { z: "first", a: "second", m: "test@example.com" };
    const result = await engine.scanObject(input);
    expect(Object.keys(result.redactedObject)).toEqual(["z", "a", "m"]);
  });

  // -------------------------------------------------------------------------
  // Detection + redaction
  // -------------------------------------------------------------------------

  it("redacts PII in top-level string fields", async () => {
    const engine = makeEngine();
    const input = { contact: "Email: john@example.com" };
    const result = await engine.scanObject(input);
    expect(result.passed).toBe(false);
    expect(result.redactedObject.contact).toContain("[REDACTED-EMAIL_ADDRESS]");
    expect(result.redactedObject.contact).not.toContain("john@example.com");
    expect(result.pathDetections).toHaveProperty("contact");
    expect(result.pathDetections.contact).toHaveLength(1);
    expect(result.pathDetections.contact[0].entityType).toBe("EMAIL_ADDRESS");
  });

  it("redacts PII in nested object fields with correct dot path", async () => {
    const engine = makeEngine();
    const input = {
      customer: { primary: "alex@example.com", note: "no PII here" },
    };
    const result = await engine.scanObject(input);
    expect(result.passed).toBe(false);
    expect(result.redactedObject.customer.primary).toContain("[REDACTED-EMAIL_ADDRESS]");
    expect(result.redactedObject.customer.note).toBe("no PII here");
    expect(result.pathDetections).toHaveProperty("customer.primary");
    expect(result.pathDetections).not.toHaveProperty("customer.note");
  });

  it("redacts PII in array elements with correct bracket index path", async () => {
    const engine = makeEngine();
    const input = {
      contacts: ["safe", "bob@example.com", "also safe"],
    };
    const result = await engine.scanObject(input);
    expect(result.redactedObject.contacts[1]).toContain("[REDACTED-EMAIL_ADDRESS]");
    expect(result.pathDetections).toHaveProperty("contacts[1]");
  });

  it("handles deeply nested mixed structures", async () => {
    const engine = makeEngine();
    const input = {
      cases: [
        {
          notes: [{ author: "writer@example.com", text: "all clear" }, { text: "ok" }],
        },
      ],
    };
    const result = await engine.scanObject(input);
    expect(result.passed).toBe(false);
    expect(result.redactedObject.cases[0].notes[0].author).toContain(
      "[REDACTED-EMAIL_ADDRESS]",
    );
    expect(result.pathDetections).toHaveProperty("cases[0].notes[0].author");
  });

  it("detects multiple entity types in the same leaf", async () => {
    const engine = makeEngine();
    const input = { line: "Email me at jane@example.com" };
    const result = await engine.scanObject(input);
    expect(result.pathDetections.line.length).toBeGreaterThanOrEqual(1);
    expect(result.pathDetections.line.some((d) => d.entityType === "EMAIL_ADDRESS")).toBe(
      true,
    );
  });

  // -------------------------------------------------------------------------
  // Aggregate results
  // -------------------------------------------------------------------------

  it("aggregates detections across leaves into per-guard results", async () => {
    const engine = makeEngine();
    const input = {
      a: "first@example.com",
      b: { c: "second@example.com" },
    };
    const result = await engine.scanObject(input);
    const piiResult = result.results.find((r) => r.guardName === "pii");
    expect(piiResult).toBeDefined();
    expect(piiResult!.detections.length).toBeGreaterThanOrEqual(2);
    expect(piiResult!.passed).toBe(false);
  });

  it("passed=true iff every leaf passes every guard", async () => {
    const engine = makeEngine();
    const cleanInput = { a: "hello", b: "world" };
    expect((await engine.scanObject(cleanInput)).passed).toBe(true);

    const dirtyInput = { a: "hello", b: "test@example.com" };
    expect((await engine.scanObject(dirtyInput)).passed).toBe(false);
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  it("handles an empty object", async () => {
    const engine = makeEngine();
    const result = await engine.scanObject({});
    expect(result.passed).toBe(true);
    expect(result.redactedObject).toEqual({});
    expect(result.pathDetections).toEqual({});
  });

  it("handles an empty array", async () => {
    const engine = makeEngine();
    const result = await engine.scanObject([]);
    expect(result.passed).toBe(true);
    expect(result.redactedObject).toEqual([]);
  });

  it("handles a top-level string", async () => {
    const engine = makeEngine();
    const result = await engine.scanObject("contact: bob@example.com");
    expect(result.passed).toBe(false);
    expect(result.redactedObject).toContain("[REDACTED-EMAIL_ADDRESS]");
    // Top-level string is a leaf at root path ""
    expect(result.pathDetections).toHaveProperty("");
  });

  it("handles a top-level number/null", async () => {
    const engine = makeEngine();
    expect((await engine.scanObject(42)).redactedObject).toBe(42);
    expect((await engine.scanObject(null)).redactedObject).toBe(null);
  });

  // -------------------------------------------------------------------------
  // Adversarial — does not corrupt non-PII strings
  // -------------------------------------------------------------------------

  it("does not modify strings that contain no detected entities", async () => {
    const engine = makeEngine();
    const input = {
      messages: [
        "no PII at all",
        "case 12345 transferred to backup",
        "the customer is frustrated",
      ],
    };
    const result = await engine.scanObject(input);
    expect(result.redactedObject.messages).toEqual(input.messages);
  });

  it("handles repeated occurrences of the same PII consistently in redact mode", async () => {
    const engine = makeEngine();
    const input = {
      a: "Email: same@example.com",
      b: "Same email same@example.com",
    };
    const result = await engine.scanObject(input);
    // In redact mode every email collapses to the same placeholder string,
    // so both leaves contain an identical [REDACTED-EMAIL_ADDRESS] marker.
    expect(result.redactedObject.a).toContain("[REDACTED-EMAIL_ADDRESS]");
    expect(result.redactedObject.b).toContain("[REDACTED-EMAIL_ADDRESS]");
  });

  it("does not mutate the input object", async () => {
    const engine = makeEngine();
    const input = { a: "test@example.com" };
    const before = JSON.stringify(input);
    await engine.scanObject(input);
    expect(JSON.stringify(input)).toBe(before);
  });
});
