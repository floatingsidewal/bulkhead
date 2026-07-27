import type { Detection } from "../types";
import { GuardrailsEngine } from "../engine/engine";
import type { DocumentCollection, LocationPlan, StringLocation } from "./types";

function propertyPath(parent: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)
    ? `${parent}.${key}`
    : `${parent}[${JSON.stringify(key)}]`;
}

/** Collect logical string locations before running any reconstruction. */
export function collectStringLocations(input: unknown): DocumentCollection {
  const locations: StringLocation[] = [];
  const plans = new Map<string, LocationPlan>();
  let nextId = 0;
  const add = (path: string, kind: StringLocation["kind"], text: string) => {
    const location: StringLocation = { id: String(nextId++), path, kind, text };
    locations.push(location);
    plans.set(location.id, { location, detections: [], selected: [] });
  };
  const walk = (value: unknown, path: string): void => {
    if (typeof value === "string") {
      add(path, "value", value);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => walk(entry, `${path}[${index}]`));
      return;
    }
    if (value !== null && typeof value === "object") {
      for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
        const childPath = propertyPath(path, key);
        add(childPath, "key", key);
        walk(entry, childPath);
      }
    }
  };
  walk(input, "$");
  return { locations, plans };
}

/**
 * Scan every collected logical string with the same registry and consistency
 * map. The guard's own redacted text is intentionally ignored: sanitization
 * applies an arbitrated plan later against original source offsets.
 */
export async function collectDetections(
  engine: GuardrailsEngine,
  collection: DocumentCollection,
): Promise<Detection[]> {
  const all: Detection[] = [];
  for (const location of collection.locations) {
    // Collection must not populate the document-wide consistency map.
    // Arbitration decides which detection owns an overlapping span before
    // any replacement is generated.
    const results = await engine.analyze(location.text);
    const plan = collection.plans.get(location.id)!;
    for (const result of results) {
      for (const detection of result.detections) {
        plan.detections.push({ location, detection });
        all.push(detection);
      }
    }
  }
  return all;
}
