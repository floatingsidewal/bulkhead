import { describe, it, expect } from "vitest";
import { GuardrailsEngine } from "../../src/engine/engine";
import { PiiGuard } from "../../src/guards/pii.guard";
import { SecretGuard } from "../../src/guards/secret.guard";
import { SynthesizerRegistry } from "../../src/synthesizers/registry";
import {
  DEFAULT_SYNTHESIZERS,
  synthEmail,
  synthIpAddress,
} from "../../src/synthesizers/defaults";
import type { Synthesizer, SynthesizerContext } from "../../src/types";

describe("synthesize mode", () => {
  // -------------------------------------------------------------------------
  // SynthesizerRegistry
  // -------------------------------------------------------------------------

  describe("SynthesizerRegistry", () => {
    it("seeds with default synthesizers", () => {
      const reg = new SynthesizerRegistry();
      expect(reg.has("EMAIL_ADDRESS")).toBe(true);
      expect(reg.has("PERSON_NAME")).toBe(true);
      expect(reg.has("PHONE_NUMBER")).toBe(true);
      expect(reg.has("CREDIT_CARD")).toBe(true);
      expect(reg.has("IP_ADDRESS")).toBe(true);
    });

    it("set() overrides defaults", () => {
      const reg = new SynthesizerRegistry();
      const custom: Synthesizer = () => "custom@override.test";
      reg.set("EMAIL_ADDRESS", custom);
      expect(reg.get("EMAIL_ADDRESS")).toBe(custom);
    });

    it("setMany() bulk-overrides", () => {
      const reg = new SynthesizerRegistry();
      reg.setMany({
        EMAIL_ADDRESS: () => "a@b.test",
        PHONE_NUMBER: () => "+1-000",
      });
      const ctx: SynthesizerContext = { detection: {} as never, consistencyMap: new Map() };
      expect(reg.get("EMAIL_ADDRESS")!("anything", ctx)).toBe("a@b.test");
      expect(reg.get("PHONE_NUMBER")!("anything", ctx)).toBe("+1-000");
    });

    it("delete() removes a synthesizer", () => {
      const reg = new SynthesizerRegistry();
      expect(reg.has("EMAIL_ADDRESS")).toBe(true);
      reg.delete("EMAIL_ADDRESS");
      expect(reg.has("EMAIL_ADDRESS")).toBe(false);
    });

    it("constructor accepts initial overrides", () => {
      const custom: Synthesizer = () => "x";
      const reg = new SynthesizerRegistry({ EMAIL_ADDRESS: custom });
      expect(reg.get("EMAIL_ADDRESS")).toBe(custom);
    });

    it("entityTypes() lists all registered types", () => {
      const reg = new SynthesizerRegistry();
      const types = reg.entityTypes();
      expect(types).toContain("EMAIL_ADDRESS");
      expect(types).toContain("CREDIT_CARD");
      expect(types.length).toBeGreaterThanOrEqual(10);
    });
  });

  // -------------------------------------------------------------------------
  // Default synthesizers — output shape
  // -------------------------------------------------------------------------

  describe("default synthesizers", () => {
    const ctx = (): SynthesizerContext => ({
      detection: {} as never,
      consistencyMap: new Map(),
    });

    it("synthEmail produces *@example.com", async () => {
      const out = await synthEmail("john.smith@contoso.com", ctx());
      expect(out).toMatch(/^[a-z]+\.[a-z]+@example\.com$/);
    });

    it("synthIpAddress produces an RFC 5737 documentation address", async () => {
      const out = await synthIpAddress("203.0.113.42", ctx());
      expect(out).toMatch(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/);
    });

    it("synthEmail is stable for the same input", async () => {
      const a = await synthEmail("user@x.com", ctx());
      const b = await synthEmail("user@x.com", ctx());
      expect(a).toBe(b);
    });

    it("different inputs produce different outputs", async () => {
      const a = await synthEmail("user1@x.com", ctx());
      const b = await synthEmail("user2@x.com", ctx());
      // Not strictly guaranteed but with hash size and 2 different inputs collisions are rare
      expect(a).not.toBe(b);
    });

    it("synthesizer reads from consistency map first", async () => {
      const consistencyMap = new Map<string, string>([["the-original", "the-replacement"]]);
      const out = await synthEmail("the-original", { detection: {} as never, consistencyMap });
      expect(out).toBe("the-replacement");
    });
  });

  // -------------------------------------------------------------------------
  // End-to-end: engine.scan with synthesize mode
  // -------------------------------------------------------------------------

  describe("engine.scan with synthesize mode", () => {
    function makeEngine(): GuardrailsEngine {
      const engine = new GuardrailsEngine({
        guards: { pii: { mode: "synthesize" } },
      });
      engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
      return engine;
    }

    it("replaces detected email with a synthetic example.com email, not [REDACTED-EMAIL_ADDRESS]", async () => {
      const engine = makeEngine();
      const { passed, redactedText, redactionMap } = await engine.scan(
        "Contact: john.smith@contoso.com",
      );
      expect(passed).toBe(false);
      expect(redactedText).toBeDefined();
      expect(redactedText).not.toContain("john.smith@contoso.com");
      expect(redactedText).not.toContain("[REDACTED-EMAIL_ADDRESS]");
      expect(redactedText).toMatch(/[a-z]+\.[a-z]+@example\.com/);
      expect(redactionMap).toHaveLength(1);
      expect(redactionMap![0].via).toBe("synthesizer");
      expect(redactionMap![0].entityType).toBe("EMAIL_ADDRESS");
      expect(redactionMap![0].original).toBe("john.smith@contoso.com");
      expect(redactionMap![0].replacement).toMatch(/@example\.com$/);
    });

    it("falls back to placeholder when no synthesizer is registered", async () => {
      const engine = new GuardrailsEngine({
        guards: { pii: { mode: "synthesize" } },
      });
      engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
      // Wipe the EMAIL_ADDRESS synthesizer
      engine.synthesizers.delete("EMAIL_ADDRESS");
      const { redactedText, redactionMap } = await engine.scan("contact: x@y.com");
      expect(redactedText).toContain("[REDACTED-EMAIL_ADDRESS]");
      expect(redactionMap![0].via).toBe("placeholder");
    });

    it("multiple mentions of the same value get the SAME synthetic replacement", async () => {
      const engine = makeEngine();
      const { redactedText, redactionMap } = await engine.scan(
        "First: same@x.com. Second: same@x.com. Third: same@x.com.",
      );
      expect(redactionMap).toHaveLength(3);
      const replacements = new Set(redactionMap!.map((r) => r.replacement));
      expect(replacements.size).toBe(1);
      // And the redacted text should contain that one replacement 3 times.
      const r = [...replacements][0];
      const matches = redactedText!.match(new RegExp(r.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"));
      expect(matches).toHaveLength(3);
    });

    it("different values get different synthetic replacements", async () => {
      const engine = makeEngine();
      const { redactionMap } = await engine.scan("a@x.com and b@y.com and c@z.com");
      const replacements = redactionMap!.map((r) => r.replacement);
      // 3 different originals expect (with very high probability) 3 different synthetics
      expect(new Set(replacements).size).toBe(3);
    });

    it("custom synthesizer override is honored", async () => {
      const engine = makeEngine();
      engine.setSynthesizers({
        EMAIL_ADDRESS: () => "custom@override.test",
      });
      const { redactedText } = await engine.scan("Mail me: real@example.org");
      expect(redactedText).toContain("custom@override.test");
      expect(redactedText).not.toContain("real@example.org");
    });

    it("redact mode (default) still produces [REDACTED-TYPE] placeholders", async () => {
      const engine = new GuardrailsEngine();
      engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
      const { redactedText, redactionMap } = await engine.scan("contact: x@y.com");
      expect(redactedText).toContain("[REDACTED-EMAIL_ADDRESS]");
      expect(redactionMap![0].via).toBe("placeholder");
    });

    it("does not modify input when no detections", async () => {
      const engine = makeEngine();
      const { passed, redactedText } = await engine.scan("nothing here");
      expect(passed).toBe(true);
      expect(redactedText).toBeUndefined();
    });

    it("aggregate redactionMap is in document order", async () => {
      const engine = makeEngine();
      const { redactionMap } = await engine.scan(
        "first: alpha@x.com middle: beta@x.com last: gamma@x.com",
      );
      expect(redactionMap![0].original).toBe("alpha@x.com");
      expect(redactionMap![1].original).toBe("beta@x.com");
      expect(redactionMap![2].original).toBe("gamma@x.com");
    });
  });

  // -------------------------------------------------------------------------
  // Cross-guard consistency
  // -------------------------------------------------------------------------

  describe("cross-guard consistency", () => {
    it("aggregate redactedText reflects all guards' detections (not just last)", async () => {
      // Repro of the pre-Phase-6 bug: prior behavior took the LAST guard's
      // redactedText and lost earlier guards' redactions.
      const engine = new GuardrailsEngine({
        guards: {
          pii: { mode: "redact" },
          secret: { mode: "redact" },
        },
      });
      engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
      engine.addGuard(new SecretGuard());
      const input =
        "Contact: alice@x.com, AWS: AKIAIOSFODNN7EXAMPLE";
      const { redactedText } = await engine.scan(input);
      expect(redactedText).toBeDefined();
      expect(redactedText).not.toContain("alice@x.com");
      expect(redactedText).not.toContain("AKIAIOSFODNN7EXAMPLE");
      expect(redactedText).toContain("[REDACTED-EMAIL_ADDRESS]");
    });

    it("aggregate redactionMap accumulates entries from all guards", async () => {
      const engine = new GuardrailsEngine({
        guards: {
          pii: { mode: "redact" },
          secret: { mode: "redact" },
        },
      });
      engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
      engine.addGuard(new SecretGuard());
      const { redactionMap } = await engine.scan(
        "Email: alice@x.com Key: AKIAIOSFODNN7EXAMPLE",
      );
      expect(redactionMap!.length).toBeGreaterThanOrEqual(2);
      const types = new Set(redactionMap!.map((r) => r.entityType));
      expect(types.has("EMAIL_ADDRESS")).toBe(true);
      // The secret guard uses its own entityType naming (e.g. "AWS_ACCESS_KEY")
      expect(types.size).toBeGreaterThanOrEqual(2);
    });
  });

  // -------------------------------------------------------------------------
  // GuardResult.redactionMap on individual guards
  // -------------------------------------------------------------------------

  describe("per-guard redactionMap", () => {
    it("PII guard populates redactionMap when in redact mode", async () => {
      const engine = new GuardrailsEngine();
      const guard = new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] });
      engine.addGuard(guard);
      const result = await guard.analyze("contact: a@b.com", { mode: "redact" });
      expect(result.redactionMap).toBeDefined();
      expect(result.redactionMap).toHaveLength(1);
      expect(result.redactionMap![0].original).toBe("a@b.com");
      expect(result.redactionMap![0].replacement).toBe("[REDACTED-EMAIL_ADDRESS]");
      expect(result.redactionMap![0].via).toBe("placeholder");
    });

    it("PII guard populates redactionMap when in synthesize mode (with engine registry)", async () => {
      const engine = new GuardrailsEngine();
      const guard = new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] });
      engine.addGuard(guard);
      // Direct guard call with redactCtx — simulates what engine.scan does.
      const result = await guard.analyze(
        "contact: a@b.com",
        { mode: "synthesize" },
        { registry: engine.synthesizers, consistencyMap: new Map() },
      );
      expect(result.redactionMap).toBeDefined();
      expect(result.redactionMap![0].via).toBe("synthesizer");
      expect(result.redactionMap![0].replacement).toMatch(/@example\.com$/);
    });

    it("redactionMap is undefined for guards with no detections", async () => {
      const guard = new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] });
      const result = await guard.analyze("nothing to see", { mode: "redact" });
      expect(result.redactionMap).toBeUndefined();
    });

    it("synthesize mode without registry falls back to placeholder", async () => {
      // No engine, no redactCtx — guard runs synthesize mode but has no
      // way to look up a synthesizer, so it falls back to placeholder.
      const guard = new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] });
      const result = await guard.analyze("contact: a@b.com", { mode: "synthesize" });
      expect(result.redactionMap![0].via).toBe("placeholder");
      expect(result.redactionMap![0].replacement).toBe("[REDACTED-EMAIL_ADDRESS]");
    });
  });

  // -------------------------------------------------------------------------
  // Adversarial
  // -------------------------------------------------------------------------

  describe("adversarial", () => {
    it("malformed URL synthesizer gracefully returns a default", async () => {
      const ctx: SynthesizerContext = { detection: {} as never, consistencyMap: new Map() };
      // synthUrl handles unparseable input
      const out = await DEFAULT_SYNTHESIZERS.URL!("not a url at all", ctx);
      expect(out).toContain("example.com");
    });

    it("empty consistency map does not crash", async () => {
      const engine = new GuardrailsEngine({
        guards: { pii: { mode: "synthesize" } },
      });
      engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
      const { redactedText } = await engine.scan("a@b.com");
      expect(redactedText).toBeDefined();
    });

    it("synthesize mode does not corrupt non-detected text", async () => {
      const engine = new GuardrailsEngine({
        guards: { pii: { mode: "synthesize" } },
      });
      engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
      const input = "Hello world! Email me at user@example.org. Goodbye world!";
      const { redactedText } = await engine.scan(input);
      expect(redactedText!.startsWith("Hello world! Email me at ")).toBe(true);
      expect(redactedText!.endsWith(". Goodbye world!")).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Policy resolver: block > synthesize > redact
  // -------------------------------------------------------------------------

  describe("policy mode merge order", () => {
    it("'eval' built-in policy is registered", async () => {
      const { getPolicy } = await import("../../src/policy/presets");
      const evalPolicy = getPolicy("eval");
      expect(evalPolicy.name).toBe("eval");
      expect(evalPolicy.guards.pii?.mode).toBe("synthesize");
      expect(evalPolicy.guards.secret?.mode).toBe("synthesize");
      expect(evalPolicy.guards.injection?.mode).toBe("redact");
    });

    it("policy merge: synthesize wins over redact (stricter)", async () => {
      const { resolvePolicy } = await import("../../src/policy/resolve");
      const base = {
        name: "base",
        description: "",
        guards: { pii: { enabled: true, threshold: 0.5, mode: "redact" as const } },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };
      const overlay = {
        name: "overlay",
        description: "",
        guards: { pii: { mode: "synthesize" as const } },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };
      const merged = resolvePolicy(base, overlay);
      expect(merged.guards.pii?.mode).toBe("synthesize");
    });

    it("policy merge: block wins over synthesize", async () => {
      const { resolvePolicy } = await import("../../src/policy/resolve");
      const base = {
        name: "base",
        description: "",
        guards: { pii: { enabled: true, threshold: 0.5, mode: "synthesize" as const } },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };
      const overlay = {
        name: "overlay",
        description: "",
        guards: { pii: { mode: "block" as const } },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };
      const merged = resolvePolicy(base, overlay);
      expect(merged.guards.pii?.mode).toBe("block");
    });

    it("policy merge: redact does NOT win over synthesize", async () => {
      const { resolvePolicy } = await import("../../src/policy/resolve");
      const base = {
        name: "base",
        description: "",
        guards: { pii: { enabled: true, threshold: 0.5, mode: "synthesize" as const } },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };
      const overlay = {
        name: "overlay",
        description: "",
        guards: { pii: { mode: "redact" as const } },
        riskThresholds: { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
      };
      const merged = resolvePolicy(base, overlay);
      expect(merged.guards.pii?.mode).toBe("synthesize");
    });
  });
});
