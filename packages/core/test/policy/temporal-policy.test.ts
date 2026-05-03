import { describe, it, expect } from "vitest";
import {
  computeTemporalReplacements,
  rebaseYearZero,
} from "../../src/policy/temporal";
import { GuardrailsEngine } from "../../src/engine/engine";
import { PiiGuard } from "../../src/guards/pii.guard";
import { resolvePolicy, getPolicy } from "../../src/policy";
import type { Detection } from "../../src/types";
import type { TemporalPolicy } from "../../src/policy/types";

function makeDateDetection(text: string, start: number): Detection {
  return {
    entityType: "DATE_TIME",
    start,
    end: start + text.length,
    text,
    confidence: "low",
    score: 0.3,
    guardName: "pii",
    source: "regex",
    context: text,
    disposition: "confirmed",
  };
}

describe("temporal policy", () => {
  // -------------------------------------------------------------------------
  // rebaseYearZero (unit)
  // -------------------------------------------------------------------------

  describe("rebaseYearZero", () => {
    it("rewrites ISO 8601 year to 0001", () => {
      expect(rebaseYearZero("2026-04-30T05:37:33Z")).toBe("0001-04-30T05:37:33Z");
    });

    it("rewrites ISO 8601 with milliseconds + offset", () => {
      expect(rebaseYearZero("2026-04-30T05:37:33.123+05:30")).toBe(
        "0001-04-30T05:37:33.123+05:30",
      );
    });

    it("rewrites yyyy-mm-dd date-only", () => {
      expect(rebaseYearZero("2026-04-30")).toBe("0001-04-30");
    });

    it("rewrites mm/dd/yyyy", () => {
      expect(rebaseYearZero("04/30/2026")).toBe("04/30/0001");
    });

    it("rewrites dd/mm/yyyy (year position is the same)", () => {
      expect(rebaseYearZero("30/04/2026")).toBe("30/04/0001");
    });

    it("returns unchanged for unrecognized format", () => {
      expect(rebaseYearZero("April 30, 2026")).toBe("April 30, 2026");
      expect(rebaseYearZero("not a date")).toBe("not a date");
    });

    it("output parses back as a valid Date", () => {
      const out = rebaseYearZero("2026-04-30T05:37:33Z");
      expect(Number.isNaN(new Date(out).getTime())).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // computeTemporalReplacements (unit)
  // -------------------------------------------------------------------------

  describe("computeTemporalReplacements", () => {
    it("returns empty map for mode=preserve", () => {
      const detections = [makeDateDetection("2026-04-30T05:37:33Z", 0)];
      const out = computeTemporalReplacements(detections, { mode: "preserve" });
      expect(out.size).toBe(0);
    });

    it("returns empty map when policy is undefined", () => {
      const detections = [makeDateDetection("2026-04-30T05:37:33Z", 0)];
      const out = computeTemporalReplacements(detections, undefined);
      expect(out.size).toBe(0);
    });

    it("ignores non-DATE_TIME detections", () => {
      const detections: Detection[] = [
        {
          entityType: "EMAIL_ADDRESS",
          start: 0,
          end: 10,
          text: "x@y.com",
          confidence: "high",
          score: 0.95,
          guardName: "pii",
          source: "regex",
          context: "x@y.com",
          disposition: "confirmed",
        },
      ];
      const out = computeTemporalReplacements(detections, { mode: "rebase-year-zero" });
      expect(out.size).toBe(0);
    });

    it("rebase-year-zero rewrites every DATE_TIME detection", () => {
      const detections = [
        makeDateDetection("2026-04-30T05:37:33Z", 0),
        makeDateDetection("2025-12-25", 100),
      ];
      const out = computeTemporalReplacements(detections, { mode: "rebase-year-zero" });
      expect(out.get("2026-04-30T05:37:33Z")).toBe("0001-04-30T05:37:33Z");
      expect(out.get("2025-12-25")).toBe("0001-12-25");
    });

    it("rebase-relative-to-earliest anchors earliest at 0001-01-01T00:00:00Z", () => {
      const earliest = "2026-04-30T05:37:33Z";
      const later = "2026-04-30T11:00:00Z"; // +5h22m27s
      const latest = "2026-05-02T18:40:59Z"; // +2d 13h 3m 26s
      const detections = [
        makeDateDetection(earliest, 0),
        makeDateDetection(later, 50),
        makeDateDetection(latest, 100),
      ];
      const out = computeTemporalReplacements(detections, {
        mode: "rebase-relative-to-earliest",
      });
      expect(out.get(earliest)).toBe("0001-01-01T00:00:00.000Z");
      expect(out.get(later)).toBe("0001-01-01T05:22:27.000Z");
      // 2d 13h 3m 26s
      expect(out.get(latest)).toBe("0001-01-03T13:03:26.000Z");
    });

    it("rebase-relative preserves total ordering of timestamps", () => {
      const detections = [
        makeDateDetection("2026-05-02T18:40:59Z", 0),
        makeDateDetection("2026-04-30T05:37:33Z", 50),
        makeDateDetection("2026-04-30T11:00:00Z", 100),
      ];
      const out = computeTemporalReplacements(detections, {
        mode: "rebase-relative-to-earliest",
      });
      const a = new Date(out.get("2026-04-30T05:37:33Z")!).getTime();
      const b = new Date(out.get("2026-04-30T11:00:00Z")!).getTime();
      const c = new Date(out.get("2026-05-02T18:40:59Z")!).getTime();
      expect(a).toBeLessThan(b);
      expect(b).toBeLessThan(c);
    });

    it("rebase-relative skips non-ISO formats (passes them through unchanged)", () => {
      const detections = [
        makeDateDetection("2026-04-30T05:37:33Z", 0),
        makeDateDetection("04/30/2026", 50),
      ];
      const out = computeTemporalReplacements(detections, {
        mode: "rebase-relative-to-earliest",
      });
      expect(out.get("2026-04-30T05:37:33Z")).toBe("0001-01-01T00:00:00.000Z");
      // mm/dd/yyyy passes through unchanged because it's ambiguous to parse
      expect(out.get("04/30/2026")).toBe("04/30/2026");
    });

    it("rebase-relative respects precision: hour", () => {
      const detections = [
        makeDateDetection("2026-04-30T05:00:00Z", 0),
        makeDateDetection("2026-04-30T05:42:33.123Z", 50),
      ];
      const out = computeTemporalReplacements(detections, {
        mode: "rebase-relative-to-earliest",
        precision: "hour",
      });
      // Earliest -> 0001-01-01T00:00:00Z
      expect(out.get("2026-04-30T05:00:00Z")).toBe("0001-01-01T00:00:00.000Z");
      // +42m33.123s rounded to hour = 0001-01-01T00:00:00Z too
      expect(out.get("2026-04-30T05:42:33.123Z")).toBe("0001-01-01T00:00:00.000Z");
    });

    it("rebase-relative respects precision: day", () => {
      const detections = [
        makeDateDetection("2026-04-30T05:37:33Z", 0),
        makeDateDetection("2026-05-02T18:40:59Z", 50),
      ];
      const out = computeTemporalReplacements(detections, {
        mode: "rebase-relative-to-earliest",
        precision: "day",
      });
      expect(out.get("2026-04-30T05:37:33Z")).toBe("0001-01-01T00:00:00.000Z");
      // +2d 13h ish, rounded to day = 0001-01-03T00:00:00Z
      expect(out.get("2026-05-02T18:40:59Z")).toBe("0001-01-03T00:00:00.000Z");
    });
  });

  // -------------------------------------------------------------------------
  // End-to-end via engine.scan
  // -------------------------------------------------------------------------

  describe("engine.scan with temporal policy", () => {
    function makeEngine(policy: TemporalPolicy | undefined): GuardrailsEngine {
      const engine = new GuardrailsEngine({
        // DATE_TIME baseScore is 0.3; lower the threshold so detections survive.
        guards: { pii: { mode: "redact", threshold: 0.2 } },
      });
      engine.addGuard(new PiiGuard({ entityTypes: ["DATE_TIME"] }));
      if (policy) engine.setTemporalPolicy(policy);
      return engine;
    }

    it("with no temporal policy, dates are redacted with placeholder", async () => {
      const engine = makeEngine(undefined);
      const { redactedText } = await engine.scan("Created: 2026-04-30T05:37:33Z");
      expect(redactedText).toContain("[REDACTED-DATE_TIME]");
      expect(redactedText).not.toContain("2026");
    });

    it("rebase-year-zero replaces detected dates with 0001-... form", async () => {
      const engine = makeEngine({ mode: "rebase-year-zero" });
      const { redactedText, redactionMap } = await engine.scan(
        "Created: 2026-04-30T05:37:33Z",
      );
      expect(redactedText).toContain("0001-04-30T05:37:33Z");
      expect(redactedText).not.toContain("2026");
      // The redaction-map entry exists but its `via` is "synthesizer" because
      // the engine fills the consistencyMap pre-pass and the guard sees a
      // cache hit. This is acceptable and documented in temporal.ts.
      expect(redactionMap).toBeDefined();
      expect(redactionMap![0].original).toBe("2026-04-30T05:37:33Z");
      expect(redactionMap![0].replacement).toBe("0001-04-30T05:37:33Z");
    });

    it("rebase-relative-to-earliest produces ordered offsets", async () => {
      const engine = makeEngine({ mode: "rebase-relative-to-earliest" });
      const input = "First: 2026-04-30T05:37:33Z. Then: 2026-04-30T11:00:00Z.";
      const { redactedText } = await engine.scan(input);
      expect(redactedText).toContain("0001-01-01T00:00:00.000Z");
      expect(redactedText).toContain("0001-01-01T05:22:27.000Z");
      expect(redactedText).not.toContain("2026");
    });

    it("preserves non-date content exactly", async () => {
      const engine = makeEngine({ mode: "rebase-year-zero" });
      const input = "Hello world! Created: 2026-04-30. Goodbye world!";
      const { redactedText } = await engine.scan(input);
      expect(redactedText!.startsWith("Hello world! Created: ")).toBe(true);
      expect(redactedText!.endsWith(". Goodbye world!")).toBe(true);
      expect(redactedText).toContain("0001-04-30");
    });

    it("setTemporalPolicy(undefined) disables transformation", async () => {
      const engine = makeEngine({ mode: "rebase-year-zero" });
      engine.setTemporalPolicy(undefined);
      const { redactedText } = await engine.scan("date: 2026-04-30");
      expect(redactedText).toContain("[REDACTED-DATE_TIME]");
      expect(redactedText).not.toContain("0001");
    });

    it("temporalPolicyConfig getter returns the active policy", () => {
      const engine = makeEngine({ mode: "rebase-year-zero" });
      expect(engine.temporalPolicyConfig?.mode).toBe("rebase-year-zero");
    });
  });

  // -------------------------------------------------------------------------
  // Built-in presets
  // -------------------------------------------------------------------------

  describe("built-in presets", () => {
    it("strict policy includes rebase-year-zero", () => {
      const strict = getPolicy("strict");
      expect(strict.temporalPolicy?.mode).toBe("rebase-year-zero");
    });

    it("moderate policy includes preserve", () => {
      const moderate = getPolicy("moderate");
      expect(moderate.temporalPolicy?.mode).toBe("preserve");
    });

    it("eval policy includes rebase-relative-to-earliest", () => {
      const evalP = getPolicy("eval");
      expect(evalP.temporalPolicy?.mode).toBe("rebase-relative-to-earliest");
      expect(evalP.temporalPolicy?.precision).toBe("ms");
    });
  });

  // -------------------------------------------------------------------------
  // Policy resolver — stricter wins
  // -------------------------------------------------------------------------

  describe("policy resolver merge", () => {
    const baseRiskThresholds = { critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 };

    it("rebase-year-zero wins over preserve", () => {
      const merged = resolvePolicy(
        {
          name: "a",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "preserve" },
        },
        {
          name: "b",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "rebase-year-zero" },
        },
      );
      expect(merged.temporalPolicy?.mode).toBe("rebase-year-zero");
    });

    it("rebase-relative-to-earliest wins over rebase-year-zero", () => {
      const merged = resolvePolicy(
        {
          name: "a",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "rebase-year-zero" },
        },
        {
          name: "b",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "rebase-relative-to-earliest" },
        },
      );
      expect(merged.temporalPolicy?.mode).toBe("rebase-relative-to-earliest");
    });

    it("preserve does NOT override rebase-year-zero", () => {
      const merged = resolvePolicy(
        {
          name: "a",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "rebase-year-zero" },
        },
        {
          name: "b",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "preserve" },
        },
      );
      expect(merged.temporalPolicy?.mode).toBe("rebase-year-zero");
    });

    it("equal modes: stricter (coarser) precision wins", () => {
      const merged = resolvePolicy(
        {
          name: "a",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "rebase-relative-to-earliest", precision: "ms" },
        },
        {
          name: "b",
          description: "",
          guards: {},
          riskThresholds: baseRiskThresholds,
          temporalPolicy: { mode: "rebase-relative-to-earliest", precision: "hour" },
        },
      );
      expect(merged.temporalPolicy?.precision).toBe("hour");
    });
  });
});
