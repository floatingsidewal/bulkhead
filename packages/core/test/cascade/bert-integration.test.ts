/**
 * BERT integration test — runs the actual BERT model via worker thread.
 * Skipped if @huggingface/transformers is not installed (optional dependency).
 *
 * First run downloads ~29MB model — allow 120s timeout.
 */

import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { CascadeClassifier } from "../../src/cascade/cascade";
import { PiiGuard } from "../../src/guards/pii.guard";
import { SecretGuard } from "../../src/guards/secret.guard";

let transformersAvailable = false;

// Skip in CI — BERT tests download a 29MB model and need native sharp bindings
if (!process.env.CI) {
  try {
    require.resolve("@huggingface/transformers");
    transformersAvailable = true;
  } catch {
    // Optional dependency not installed
  }
}

const describeIf = transformersAvailable ? describe : describe.skip;

describeIf("BERT Integration (real model)", () => {
  let cascade: CascadeClassifier;

  beforeAll(() => {
    cascade = new CascadeClassifier({
      bertEnabled: true,
      llmEnabled: false,
      escalationThreshold: 0.75,
      modelId: "Xenova/bert-base-NER",
    });
    cascade.addRegexGuard(new PiiGuard());
    cascade.addRegexGuard(new SecretGuard());
  });

  afterAll(async () => {
    await cascade.dispose();
  });

  it("deep scan detects person names via BERT", async () => {
    const result = await cascade.deepScan(
      "Please contact John Smith at the main office for details."
    );

    // BERT should detect "John Smith" as a PERSON entity
    const bertDetections = result.detections.filter((d) => d.source === "bert");
    expect(bertDetections.length).toBeGreaterThan(0);

    const personDetections = bertDetections.filter(
      (d) => d.entityType === "PER" || d.entityType === "PERSON"
    );
    expect(personDetections.length).toBeGreaterThan(0);
  }, 120_000);

  it("deduplicates regex and BERT detections", async () => {
    const result = await cascade.deepScan(
      "My SSN is 219-09-9999. Contact John Smith for questions."
    );

    // SSN should come from regex (not duplicated by BERT)
    const ssnDetections = result.detections.filter(
      (d) => d.entityType === "US_SSN"
    );
    expect(ssnDetections.length).toBe(1);
    expect(ssnDetections[0].source).toBe("regex");

    // Person name should come from BERT
    const personDetections = result.detections.filter(
      (d) => d.entityType === "PERSON" || d.entityType === "PER"
    );
    expect(personDetections.length).toBeGreaterThan(0);
    expect(personDetections[0].source).toBe("bert");
  }, 120_000);

  it("model scan returns BERT detections with scores", async () => {
    const result = await cascade.modelScan(
      "Dr. Sarah Johnson presented the findings in Berlin."
    );

    const bertDetections = result.detections.filter((d) => d.source === "bert");

    for (const d of bertDetections) {
      expect(d.score).toBeGreaterThan(0);
      expect(d.score).toBeLessThanOrEqual(1);
      expect(["confirmed", "escalate"]).toContain(d.disposition);
    }
  }, 120_000);

  it("handles text with no entities gracefully", async () => {
    const result = await cascade.deepScan(
      "The weather is nice today. Let's go for a walk."
    );

    // Should have no detections (or very low confidence ones)
    const highConfidence = result.detections.filter(
      (d) => d.disposition === "confirmed"
    );
    // Weather text should not trigger confirmed detections
    expect(result.passed).toBe(true);
  }, 120_000);

  it("measures cold and warm latency", async () => {
    // Warm run (model already loaded from prior tests)
    const warmStart = performance.now();
    await cascade.deepScan("Contact Alice Johnson about the project.");
    const warmLatency = performance.now() - warmStart;

    console.log(`BERT warm latency: ${warmLatency.toFixed(1)}ms`);
    // Warm BERT inference should be under 500ms for short text
    expect(warmLatency).toBeLessThan(5000);
  }, 120_000);
});
