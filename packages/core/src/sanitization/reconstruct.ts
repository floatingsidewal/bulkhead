import type { JsonValue } from "../types";
import type { DocumentCollection, LocationPlan, ReconstructedDocument } from "./types";

function propertyPath(parent: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)
    ? `${parent}.${key}`
    : `${parent}[${JSON.stringify(key)}]`;
}

function applyPlan(source: string, plan: LocationPlan): string {
  const selected = plan.selected;
  let output = source;
  for (const treatment of [...selected].sort((a, b) => b.start - a.start)) {
    output = output.slice(0, treatment.start) + treatment.replacement + output.slice(treatment.end);
  }
  return output;
}

/** Reconstruct JSON natively; no serialized JSON is ever used as a mutation target. */
export function reconstructDocument(input: JsonValue, collection: DocumentCollection): ReconstructedDocument {
  const emitted = new Map<string, string>();
  const keyCollisions: Array<{ path: string; replacement: string }> = [];
  let locationId = 0;
  const take = () => collection.plans.get(String(locationId++))!;
  const walk = (value: JsonValue, path: string): JsonValue => {
    if (typeof value === "string") {
      const plan = take();
      const output = applyPlan(value, plan);
      emitted.set(plan.location.id, output);
      return output;
    }
    if (Array.isArray(value)) return value.map((entry, index) => walk(entry, `${path}[${index}]`));
    if (value !== null && typeof value === "object") {
      const output: Record<string, JsonValue> = {};
      for (const [key, entry] of Object.entries(value)) {
        const plan = take();
        const sanitizedKey = applyPlan(key, plan);
        let collisionSafeKey = sanitizedKey;
        let collisionIndex = 1;
        while (Object.prototype.hasOwnProperty.call(output, collisionSafeKey)) {
          collisionSafeKey = `[REDACTED-KEY-${collisionIndex++}]`;
        }
        if (collisionSafeKey !== sanitizedKey) {
          keyCollisions.push({ path: plan.location.path, replacement: collisionSafeKey });
        }
        emitted.set(plan.location.id, collisionSafeKey);
        // defineProperty preserves JSON keys such as "__proto__" as own
        // entries instead of invoking Object.prototype's legacy setter.
        Object.defineProperty(output, collisionSafeKey, {
          value: walk(entry, propertyPath(path, key)),
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
      return output;
    }
    return value;
  };
  return { value: walk(input, "$"), emitted, keyCollisions };
}
