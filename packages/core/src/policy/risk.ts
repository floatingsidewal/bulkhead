import type { GuardResult } from "../types";
import type {
  PolicyDefinition,
  RiskAssessment,
  RiskLevel,
  ClassifiedIssue,
  TestDataFlag,
} from "./types";

/**
 * Compute a risk assessment from guard results and a policy definition.
 * Pure function — no side effects, no engine mutation.
 */
export function assessRisk(
  results: GuardResult[],
  policy: PolicyDefinition
): RiskAssessment {
  const allDetections = results.flatMap((r) => r.detections);

  // Separate test-data detections from real detections
  const testDetections = allDetections.filter((d) =>
    d.entityType.startsWith("TEST_DATA_")
  );
  const realDetections = allDetections.filter(
    (d) => !d.entityType.startsWith("TEST_DATA_")
  );

  // Build test data flags
  const testDataFlags: TestDataFlag[] = testDetections.map((d) => ({
    value: d.text,
    reason: d.entityType.toLowerCase().replace("test_data_", "") + "-pattern",
    start: d.start,
    end: d.end,
  }));

  // Aggregate score from real detections only
  // (test data shouldn't inflate the risk score)
  const score =
    realDetections.length > 0
      ? Math.max(...realDetections.map((d) => d.score))
      : 0;

  const level = scoreToLevel(score, policy.riskThresholds);

  // Per-guard breakdown (excluding testdata guard)
  const guards: RiskAssessment["guards"] = {};
  for (const result of results) {
    if (result.guardName === "testdata") continue;
    const guardDetections = result.detections.filter(
      (d) => !d.entityType.startsWith("TEST_DATA_")
    );
    guards[result.guardName] = {
      level: scoreToLevel(result.score, policy.riskThresholds),
      score: result.score,
      detectionCount: guardDetections.length,
    };
  }

  // Classify issues by entity type
  const issues = classifyIssues(realDetections, testDetections, policy);

  return { level, score, guards, issues, testDataFlags };
}

function scoreToLevel(
  score: number,
  thresholds: PolicyDefinition["riskThresholds"]
): RiskLevel {
  if (score >= thresholds.critical) return "critical";
  if (score >= thresholds.high) return "high";
  if (score >= thresholds.medium) return "medium";
  if (score >= thresholds.low) return "low";
  return "none";
}

function classifyIssues(
  realDetections: GuardResult["detections"],
  testDetections: GuardResult["detections"],
  policy: PolicyDefinition
): ClassifiedIssue[] {
  // Group real detections by guardName + entityType
  const groups = new Map<
    string,
    { detections: typeof realDetections; guardName: string; entityType: string }
  >();

  for (const d of realDetections) {
    const key = `${d.guardName}:${d.entityType}`;
    const group = groups.get(key);
    if (group) {
      group.detections.push(d);
    } else {
      groups.set(key, {
        detections: [d],
        guardName: d.guardName,
        entityType: d.entityType,
      });
    }
  }

  const issues: ClassifiedIssue[] = [];

  for (const [, group] of groups) {
    const maxScore = Math.max(...group.detections.map((d) => d.score));
    const severity = scoreToLevel(maxScore, policy.riskThresholds);

    // Check if any detection in this group overlaps with test data
    const isTestData = group.detections.some((d) =>
      testDetections.some(
        (td) => d.start < td.end && d.end > td.start
      )
    );

    const category = guardNameToCategory(group.guardName);
    const sample = group.detections[0]?.text?.slice(0, 50);

    issues.push({
      category,
      entityType: group.entityType,
      severity,
      count: group.detections.length,
      isTestData,
      sample,
    });
  }

  // Sort: critical first, then by count
  return issues.sort((a, b) => {
    const levelOrder: Record<RiskLevel, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      none: 4,
    };
    const levelDiff = levelOrder[a.severity] - levelOrder[b.severity];
    if (levelDiff !== 0) return levelDiff;
    return b.count - a.count;
  });
}

function guardNameToCategory(
  guardName: string
): ClassifiedIssue["category"] {
  switch (guardName) {
    case "pii":
      return "pii";
    case "secret":
      return "secret";
    case "injection":
      return "injection";
    case "leakage":
      return "leakage";
    default:
      return "pii"; // fallback for cascade-bert etc
  }
}
