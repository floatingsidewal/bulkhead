import * as vscode from "vscode";
import type { GuardrailsEngine } from "../engine/engine";
import { resultsToDiagnostics } from "./diagnostics";

export function registerCommands(
  context: vscode.ExtensionContext,
  engine: GuardrailsEngine,
  diagnosticCollection: vscode.DiagnosticCollection
): void {
  // Scan file command
  context.subscriptions.push(
    vscode.commands.registerCommand("bulkhead.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("No active editor to scan.");
        return;
      }

      const text = editor.document.getText();
      const results = await engine.analyze(text);
      const diagnostics = resultsToDiagnostics(editor.document, results);
      diagnosticCollection.set(editor.document.uri, diagnostics);

      const issueCount = diagnostics.length;
      if (issueCount === 0) {
        vscode.window.showInformationMessage("Bulkhead: No issues found.");
      } else {
        vscode.window.showWarningMessage(
          `Bulkhead: Found ${issueCount} issue${issueCount > 1 ? "s" : ""}.`
        );
      }
    })
  );

  // Dismiss diagnostic command
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "bulkhead.dismissDiagnostic",
      (diagnostic: vscode.Diagnostic) => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;

        const existing = diagnosticCollection.get(editor.document.uri) ?? [];
        const filtered = [...existing].filter((d) => d !== diagnostic);
        diagnosticCollection.set(editor.document.uri, filtered);
      }
    )
  );

  // Placeholder for content safety check (LLM-based, Phase 4)
  context.subscriptions.push(
    vscode.commands.registerCommand("bulkhead.checkContentSafety", async () => {
      vscode.window.showInformationMessage(
        "Bulkhead: Content safety checks require LLM configuration. Coming soon."
      );
    })
  );
}
