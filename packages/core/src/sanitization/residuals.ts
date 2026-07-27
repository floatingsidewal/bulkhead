import type { ResidualFinding } from "../types";
import type { DocumentCollection, ReconstructedDocument } from "./types";

/** Validate source survival at logical keys and values, never serialized JSON. */
export function findResiduals(
  collection: DocumentCollection,
  reconstructed: ReconstructedDocument,
): ResidualFinding[] {
  const residuals: ResidualFinding[] = [];
  for (const plan of collection.plans.values()) {
    const emitted = reconstructed.emitted.get(plan.location.id) ?? "";
    for (const collected of plan.detections) {
      const treatment = plan.selected.find(
        (candidate) =>
          candidate.start <= collected.detection.start &&
          candidate.end >= collected.detection.end,
      );
      if (!treatment) {
        residuals.push({
          category: collected.detection.entityType,
          path: plan.location.path,
          reason: "untreated-detection",
        });
      } else if (emitted.includes(collected.detection.text)) {
        residuals.push({
          category: collected.detection.entityType,
          path: plan.location.path,
          reason: "surviving-source-value",
        });
      }
    }
  }
  return residuals;
}
