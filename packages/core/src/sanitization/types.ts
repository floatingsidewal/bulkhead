import type { Detection, JsonValue, RedactionEntry } from "../types";

export type LogicalPath = string;
export type LocationKind = "key" | "value";

export interface StringLocation {
  id: string;
  path: LogicalPath;
  kind: LocationKind;
  text: string;
}

export interface CollectedDetection {
  location: StringLocation;
  detection: Detection;
}

/**
 * A selected treatment has one source interval and is created only after
 * arbitration. `selected` is therefore non-overlapping for a location.
 */
export interface SelectedTreatment {
  locationId: string;
  start: number;
  end: number;
  replacement: string;
  entityType: string;
  kind: "replaced" | "rebased" | "merged-redaction";
  detections: CollectedDetection[];
  provenance?: RedactionEntry["via"] | "temporal" | "neutral";
}

export interface LocationPlan {
  location: StringLocation;
  detections: CollectedDetection[];
  selected: SelectedTreatment[];
}

export interface DocumentCollection {
  locations: StringLocation[];
  plans: Map<string, LocationPlan>;
}

export interface ReconstructedDocument {
  value: JsonValue;
  /** The actual text emitted for every logical key and value. */
  emitted: Map<string, string>;
  keyCollisions: Array<{ path: string; replacement: string }>;
}
