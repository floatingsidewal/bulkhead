import * as vscode from "vscode";
import type { GuardrailsEngine } from "../engine/engine";
import { resultsToDiagnostics } from "./diagnostics";

export function registerCommands(
  context: vscode.ExtensionContext,
  engine: GuardrailsEngine,
  diagnosticCollection: vscode.DiagnosticCollection
): void {
  // Scan file — Layer 1 (regex) only, fast
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

  // Deep scan — Full cascade: regex + BERT + LLM disambiguation
  context.subscriptions.push(
    vscode.commands.registerCommand("bulkhead.deepScan", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("No active editor to scan.");
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "Bulkhead: Deep scanning...",
          cancellable: false,
        },
        async () => {
          const text = editor.document.getText();
          const results = await engine.deepScan(text);
          const diagnostics = resultsToDiagnostics(editor.document, results);
          diagnosticCollection.set(editor.document.uri, diagnostics);

          const confirmed = diagnostics.filter(
            (d) => !d.message.includes("needs review")
          );
          const escalated = diagnostics.filter((d) =>
            d.message.includes("needs review")
          );

          const parts: string[] = [];
          if (confirmed.length > 0)
            parts.push(`${confirmed.length} confirmed`);
          if (escalated.length > 0)
            parts.push(`${escalated.length} need review`);

          if (parts.length === 0) {
            vscode.window.showInformationMessage(
              "Bulkhead: No issues found."
            );
          } else {
            vscode.window.showWarningMessage(
              `Bulkhead: Found ${parts.join(", ")}.`
            );
          }
        }
      );
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

  // Content safety check placeholder (Layer 3 LLM)
  context.subscriptions.push(
    vscode.commands.registerCommand("bulkhead.checkContentSafety", async () => {
      vscode.window.showInformationMessage(
        "Bulkhead: Content safety checks require LLM configuration. Coming soon."
      );
    })
  );
}
