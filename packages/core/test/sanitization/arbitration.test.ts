import { describe, expect, it } from "vitest";
import { arbitrateDetections } from "../../src/sanitization/arbitration";
import type { CollectedDetection, StringLocation } from "../../src/sanitization/types";

const location: StringLocation = { id: "0", path: "$.value", kind: "value", text: "abcdefghijkl" };
function detection(
  start: number,
  end: number,
  entityType: string,
  guardName = "pii",
  confidence: "medium",
): CollectedDetection {
  return {
    location,
    detection: {
      start, end, entityType, guardName, confidence: confidence as "high" | "medium" | "low",
      score: confidence === "high" ? 0.9 : 0.5, text: location.text.slice(start, end),
      source: "regex", context: location.text, disposition: "confirmed",
    },
  };
}

describe("document arbitration", () => {
  it("uses a neutral union when the strongest containment detection is inner", () => {
    const contained = [
      detection(0, 12, "URL", "pii", "medium"),
      detection(4, 10, "EMAIL_ADDRESS", "pii", "high"),
    ];
    const selected = arbitrateDetections(contained);
    expect(selected).toHaveLength(1);
    expect(selected[0]).toMatchObject({
      start: 0,
      end: 12,
      entityType: "OVERLAPPING_RISK",
    });
  });

  it("chooses the strongest detection when equal spans cover the component", () => {
    const selected = arbitrateDetections([
      detection(0, 12, "URL", "pii", "medium"),
      detection(0, 12, "AWS_KEY", "secret", "low"),
    ]);
    expect(selected).toHaveLength(1);
    expect(selected[0]).toMatchObject({ start: 0, end: 12, entityType: "AWS_KEY" });
  });

  it("uses a neutral union for partial intersections", () => {
    const selected = arbitrateDetections([
      detection(1, 7, "URL"),
      detection(5, 11, "EMAIL_ADDRESS"),
    ]);
    expect(selected).toHaveLength(1);
    expect(selected[0]).toMatchObject({ start: 1, end: 11, entityType: "OVERLAPPING_RISK" });
  });

  it("is stable under detection order permutations and never overlaps", () => {
    const detections = [
      detection(0, 2, "A"),
      detection(3, 8, "B"),
      detection(6, 10, "C"),
      detection(11, 12, "D"),
    ];
    const first = arbitrateDetections(detections);
    const second = arbitrateDetections([...detections].reverse());
    expect(second).toEqual(first);
    for (let i = 1; i < first.length; i++) {
      expect(first[i - 1].end).toBeLessThanOrEqual(first[i].start);
    }
  });
});
