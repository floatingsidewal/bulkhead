import { describe, it, expect } from "vitest";
import { GuardrailsEngine } from "../../src/engine/engine";
import { PiiGuard } from "../../src/guards/pii.guard";
import { SecretGuard } from "../../src/guards/secret.guard";
import { InjectionGuard } from "../../src/guards/injection.guard";

describe("GuardrailsEngine", () => {
  it("runs multiple guards", async () => {
    const engine = new GuardrailsEngine();
    engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));
    engine.addGuard(new SecretGuard());

    const results = await engine.analyze("Email: test@example.com, Key: AKIAIOSFODNN7EXAMPLE");
    expect(results).toHaveLength(2);
    expect(results[0].guardName).toBe("pii");
    expect(results[1].guardName).toBe("secret");
  });

  it("scan returns overall pass/fail", async () => {
    const engine = new GuardrailsEngine();
    engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));

    const { passed } = await engine.scan("No sensitive data here");
    expect(passed).toBe(true);

    const { passed: failed } = await engine.scan("Email: test@example.com");
    expect(failed).toBe(false);
  });

  it("respects disabled guards via config", async () => {
    const engine = new GuardrailsEngine({
      guards: { pii: { enabled: false } },
    });
    engine.addGuard(new PiiGuard({ entityTypes: ["EMAIL_ADDRESS"] }));

    const results = await engine.analyze("Email: test@example.com");
    expect(results).toHaveLength(0);
  });

  it("addGuards registers multiple guards", () => {
    const engine = new GuardrailsEngine();
    engine.addGuards([new PiiGuard(), new SecretGuard(), new InjectionGuard()]);
    expect(engine.guardNames).toEqual(["pii", "secret", "injection"]);
  });
});
