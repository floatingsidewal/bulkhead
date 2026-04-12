import * as vscode from "vscode";
import type { GuardResult, Detection } from "@bulkhead-ai/core";

export const DIAGNOSTIC_COLLECTION_NAME = "bulkhead";

export function createDiagnosticCollection(): vscode.DiagnosticCollection {
  return vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
}

/** Convert guard results to VS Code diagnostics for a document */
export function resultsToDiagnostics(
  document: vscode.TextDocument,
  results: GuardResult[]
): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];

  for (const result of results) {
    if (result.passed) continue;

    for (const detection of result.detections) {
      const startPos = document.positionAt(detection.start);
      const endPos = document.positionAt(detection.end);
      const range = new vscode.Range(startPos, endPos);

      const severity = getSeverity(detection);
      const sourceLabel = detection.source ?? "regex";
      const dispositionSuffix =
        detection.disposition === "escalate" ? " (needs review)" : "";
      const diagnostic = new vscode.Diagnostic(
        range,
        `[Bulkhead/${sourceLabel}] ${detection.entityType}: ${detection.text.slice(0, 50)}${detection.text.length > 50 ? "..." : ""}${dispositionSuffix}`,
        severity
      );

      diagnostic.source = "bulkhead";
      diagnostic.code = detection.entityType;
      diagnostics.push(diagnostic);
    }
  }

  return diagnostics;
}

function getSeverity(detection: Detection): vscode.DiagnosticSeverity {
  if (detection.disposition === "escalate")
    return vscode.DiagnosticSeverity.Information;
  if (detection.disposition === "dismissed")
    return vscode.DiagnosticSeverity.Hint;
  if (detection.guardName === "secret") return vscode.DiagnosticSeverity.Error;
  if (detection.guardName === "injection") return vscode.DiagnosticSeverity.Error;
  if (detection.confidence === "high") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}
