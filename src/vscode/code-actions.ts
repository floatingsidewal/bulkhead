import * as vscode from "vscode";
import { DIAGNOSTIC_COLLECTION_NAME } from "./diagnostics";

export class BulkheadCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "bulkhead") continue;

      // Redact action
      const redactAction = new vscode.CodeAction(
        `Redact ${diagnostic.code}`,
        vscode.CodeActionKind.QuickFix
      );
      redactAction.edit = new vscode.WorkspaceEdit();
      redactAction.edit.replace(
        document.uri,
        diagnostic.range,
        `[REDACTED-${diagnostic.code}]`
      );
      redactAction.diagnostics = [diagnostic];
      redactAction.isPreferred = true;
      actions.push(redactAction);

      // Dismiss action
      const dismissAction = new vscode.CodeAction(
        `Dismiss this ${diagnostic.code} warning`,
        vscode.CodeActionKind.QuickFix
      );
      dismissAction.command = {
        command: "bulkhead.dismissDiagnostic",
        title: "Dismiss",
        arguments: [diagnostic],
      };
      dismissAction.diagnostics = [diagnostic];
      actions.push(dismissAction);
    }

    return actions;
  }
}
