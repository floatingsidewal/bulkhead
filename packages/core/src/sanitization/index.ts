import {
  GuardrailsEngine,
} from "../engine/engine";
import { PiiGuard } from "../guards/pii.guard";
import { SecretGuard } from "../guards/secret.guard";
import { InjectionGuard } from "../guards/injection.guard";
import { LeakageGuard } from "../guards/leakage.guard";
import { TestDataGuard } from "../guards/testdata.guard";
import { planReplacement } from "../guards/base.guard";
import { policyToEngineConfig, resolveRef } from "../policy/resolve";
import { planTemporalReplacements } from "../policy/temporal";
import type { PolicyDefinition } from "../policy/types";
import type {
  DetectionSummary,
  JsonValue,
  RedactContext,
  SanitizeDocumentOptions,
  SanitizeResult,
} from "../types";
import { arbitrateDetections } from "./arbitration";
import { collectDetections, collectStringLocations } from "./collect";
import { reconstructDocument } from "./reconstruct";
import { findResiduals } from "./residuals";

export type SanitizePolicy = string | PolicyDefinition;

function createDocumentEngine(policy: PolicyDefinition): {
  engine: GuardrailsEngine;
  modes: Record<string, "block" | "redact" | "synthesize" | undefined>;
  excluded: Set<string>;
} {
  const engine = new GuardrailsEngine();
  const { piiOptions, secretOptions, guardConfigs } = policyToEngineConfig(policy);
  if (policy.guards.pii?.enabled !== false) engine.addGuard(new PiiGuard(piiOptions));
  if (policy.guards.secret?.enabled !== false) engine.addGuard(new SecretGuard(secretOptions));
  if (policy.guards.injection?.enabled !== false) engine.addGuard(new InjectionGuard());
  if (policy.guards.leakage?.enabled !== false) engine.addGuard(new LeakageGuard());
  if (policy.testDataDetection !== "ignore") engine.addGuard(new TestDataGuard());
  engine.updateConfig({ guards: guardConfigs });
  const excluded = new Set<string>();
  for (const guard of Object.values(policy.guards)) {
    guard?.excludeEntities?.forEach((entity) => excluded.add(entity));
  }
  return {
    engine,
    modes: Object.fromEntries(
      Object.entries(guardConfigs).map(([name, config]) => [name, config.mode]),
    ),
    excluded,
  };
}

function structurallyValid(value: JsonValue): boolean {
  const jsonCompatible = (candidate: unknown): boolean => {
    if (candidate === null || typeof candidate === "string" || typeof candidate === "boolean") {
      return true;
    }
    if (typeof candidate === "number") return Number.isFinite(candidate) && !Object.is(candidate, -0);
    if (Array.isArray(candidate)) return candidate.every(jsonCompatible);
    if (typeof candidate === "object") {
      return Object.values(candidate as Record<string, unknown>).every(jsonCompatible);
    }
    return false;
  };
  try {
    if (!jsonCompatible(value)) return false;
    const serialized = JSON.stringify(value);
    if (serialized === undefined) return false;
    return JSON.stringify(JSON.parse(serialized)) === serialized;
  } catch {
    return false;
  }
}

/**
 * Sanitize a JSON-compatible document using one collection pass, one
 * consistency map, and object-native reconstruction. Existing scan APIs are
 * intentionally untouched; this is the fail-closed document-level API.
 */
export async function sanitizeDocument<T extends JsonValue>(
  input: T,
  policyRef: SanitizePolicy,
  options: SanitizeDocumentOptions = {},
): Promise<SanitizeResult<T>> {
  const policy = resolveRef(policyRef);
  const { engine, modes, excluded } = createDocumentEngine(policy);
  const context: RedactContext = {
    registry: engine.synthesizers,
    consistencyMap: new Map<string, string>(),
  };
  const collection = collectStringLocations(input);
  const detections = await collectDetections(engine, collection);
  const temporal = planTemporalReplacements(
    detections,
    policy.temporalPolicy,
    options.localizedDateOrder ?? policy.localizedDateOrder ?? "reject-ambiguous",
    options.detectedUnparseableDateReplacement ??
      policy.detectedUnparseableDateReplacement ??
      "[REDACTED-DATE_TIME]",
  );
  for (const [source, replacement] of temporal.replacements) {
    context.consistencyMap!.set(source, replacement);
  }

  for (const plan of collection.plans.values()) {
    const active = plan.detections.filter(
      (collected) => !excluded.has(collected.detection.entityType),
    );
    for (const selected of arbitrateDetections(active)) {
      if (selected.entityType === "OVERLAPPING_RISK") {
        plan.selected.push({
          ...selected,
          replacement: "[REDACTED]",
          kind: "merged-redaction",
          provenance: "neutral",
        });
        continue;
      }
      const selectedDetection =
        selected.detections.find(
          (collected) =>
            collected.detection.start === selected.start &&
            collected.detection.end === selected.end &&
            collected.detection.entityType === selected.entityType,
        ) ?? selected.detections[0];
      const temporalReplacement = temporal.replacements.get(selectedDetection.detection.text);
      if (temporalReplacement !== undefined) {
        plan.selected.push({
          ...selected,
          replacement: temporalReplacement,
          kind:
            policy.temporalPolicy?.mode === "rebase-year-zero" ||
            policy.temporalPolicy?.mode === "rebase-relative-to-earliest"
              ? "rebased"
              : "replaced",
          provenance: "temporal",
        });
        continue;
      }
      const entry = await planReplacement(
        selectedDetection.detection,
        modes[selectedDetection.detection.guardName] ?? "redact",
        context,
      );
      plan.selected.push({
        ...selected,
        replacement: entry.replacement,
        kind: "replaced",
        provenance: entry.via,
      });
    }
  }

  const reconstructed = reconstructDocument(input, collection);
  const residuals = findResiduals(collection, reconstructed);
  const categories: Record<string, number> = {};
  const summaries: DetectionSummary[] = [];
  for (const plan of collection.plans.values()) {
    for (const collected of plan.detections) {
      categories[collected.detection.entityType] =
        (categories[collected.detection.entityType] ?? 0) + 1;
      const treatment = plan.selected.find(
        (candidate) =>
          candidate.start <= collected.detection.start &&
          candidate.end >= collected.detection.end,
      );
      summaries.push({
        category: collected.detection.entityType,
        sourcePath: collected.location.path,
        sourceSpan: { start: collected.detection.start, end: collected.detection.end },
        treatment: treatment?.kind ?? "untreated",
      });
    }
  }
  const valid = structurallyValid(reconstructed.value);
  return {
    value: reconstructed.value as T,
    metadata: {
      detectedRisk: { count: detections.length, categories, detections: summaries },
      postTreatment: { safe: valid && residuals.length === 0, residuals, structurallyValid: valid },
      ...(temporal.temporalAnchor ? { temporalAnchor: temporal.temporalAnchor } : {}),
      ...(reconstructed.keyCollisions.length > 0
        ? { keyCollisions: reconstructed.keyCollisions }
        : {}),
    },
  };
}
