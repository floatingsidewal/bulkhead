import type { CollectedDetection, SelectedTreatment } from "./types";

const GUARD_PRECEDENCE: Record<string, number> = {
  secret: 50,
  pii: 40,
  leakage: 30,
  injection: 20,
  testdata: 10,
};

const CONFIDENCE_PRECEDENCE: Record<string, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

function overlaps(a: CollectedDetection, b: CollectedDetection): boolean {
  return a.detection.start < b.detection.end && b.detection.start < a.detection.end;
}

function contains(a: CollectedDetection, b: CollectedDetection): boolean {
  return a.detection.start <= b.detection.start && a.detection.end >= b.detection.end;
}

function winner(a: CollectedDetection, b: CollectedDetection): CollectedDetection {
  const byGuard =
    (GUARD_PRECEDENCE[b.detection.guardName] ?? 0) -
    (GUARD_PRECEDENCE[a.detection.guardName] ?? 0);
  if (byGuard !== 0) return byGuard > 0 ? b : a;
  const byConfidence =
    (CONFIDENCE_PRECEDENCE[b.detection.confidence] ?? 0) -
    (CONFIDENCE_PRECEDENCE[a.detection.confidence] ?? 0);
  if (byConfidence !== 0) return byConfidence > 0 ? b : a;
  if (a.detection.score !== b.detection.score) {
    return b.detection.score > a.detection.score ? b : a;
  }
  const aLength = a.detection.end - a.detection.start;
  const bLength = b.detection.end - b.detection.start;
  if (aLength !== bLength) return bLength > aLength ? b : a;
  const aKey = `${a.detection.entityType}:${a.detection.guardName}`;
  const bKey = `${b.detection.entityType}:${b.detection.guardName}`;
  return bKey < aKey ? b : a;
}

/**
 * Resolve a location's overlapping spans independent of the order in which
 * guards returned them. Partial intersections are deliberately collapsed to
 * one neutral union treatment; containment and equal spans have a sound
 * winner selected by the fixed guard/confidence/length precedence above.
 */
export function arbitrateDetections(
  detections: CollectedDetection[],
): Array<Omit<SelectedTreatment, "replacement" | "kind" | "provenance">> {
  const sorted = [...detections].sort(
    (a, b) =>
      a.detection.start - b.detection.start ||
      a.detection.end - b.detection.end ||
      a.detection.guardName.localeCompare(b.detection.guardName) ||
      a.detection.entityType.localeCompare(b.detection.entityType),
  );
  const components: CollectedDetection[][] = [];
  for (const detection of sorted) {
    const last = components[components.length - 1];
    if (last && last.some((existing) => overlaps(existing, detection))) last.push(detection);
    else components.push([detection]);
  }

  return components.map((component) => {
    const locationId = component[0].location.id;
    if (component.length === 1) {
      const only = component[0];
      return {
        locationId,
        start: only.detection.start,
        end: only.detection.end,
        entityType: only.detection.entityType,
        detections: component,
      };
    }

    const needsUnion = component.some((candidate, index) =>
      component.slice(index + 1).some(
        (other) => !contains(candidate, other) && !contains(other, candidate),
      ),
    );
    if (needsUnion) {
      return {
        locationId,
        start: Math.min(...component.map((d) => d.detection.start)),
        end: Math.max(...component.map((d) => d.detection.end)),
        entityType: "OVERLAPPING_RISK",
        detections: component,
      };
    }
    // A containment winner must cover every source detection. If the strongest
    // detection is an inner span (for example, a credential inside a URL),
    // applying the outer detection's synthesizer could preserve the inner
    // secret. In that case there is no sound winner, so redact the union.
    let strongest = component[0];
    for (const candidate of component.slice(1)) strongest = winner(strongest, candidate);
    const covering = component.filter((candidate) =>
      component.every((other) => contains(candidate, other)),
    );
    if (!covering.includes(strongest)) {
      return {
        locationId,
        start: Math.min(...component.map((d) => d.detection.start)),
        end: Math.max(...component.map((d) => d.detection.end)),
        entityType: "OVERLAPPING_RISK",
        detections: component,
      };
    }
    let selected = covering[0];
    for (const candidate of covering.slice(1)) selected = winner(selected, candidate);
    return {
      locationId,
      start: selected.detection.start,
      end: selected.detection.end,
      entityType: selected.detection.entityType,
      detections: component,
    };
  });
}
