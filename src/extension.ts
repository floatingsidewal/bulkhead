import * as vscode from "vscode";
import { GuardrailsEngine } from "./engine/engine";
import { PiiGuard } from "./guards/pii.guard";
import { SecretGuard } from "./guards/secret.guard";
import { InjectionGuard } from "./guards/injection.guard";
import { LeakageGuard } from "./guards/leakage.guard";
import { getConfig } from "./vscode/config";
import {
  createDiagnosticCollection,
  resultsToDiagnostics,
} from "./vscode/diagnostics";
import { BulkheadCodeActionProvider } from "./vscode/code-actions";
import { registerCommands } from "./vscode/commands";

let engine: GuardrailsEngine;
let diagnosticCollection: vscode.DiagnosticCollection;
let debounceTimer: ReturnType<typeof setTimeout> | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = createDiagnosticCollection();
  context.subscriptions.push(diagnosticCollection);

  // Initialize engine with guards + cascade
  engine = createEngine();

  // Register code action provider for all file types
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new BulkheadCodeActionProvider(),
      { providedCodeActionKinds: BulkheadCodeActionProvider.providedCodeActionKinds }
    )
  );

  // Register commands
  registerCommands(context, engine, diagnosticCollection);

  // Auto-scan on document change (debounced) — Layer 1 only (regex, sub-ms)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = getConfig();
      if (!config.enabled) return;

      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        scanDocument(event.document);
      }, config.debounceMs);
    })
  );

  // Scan on document open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((document) => {
      const config = getConfig();
      if (!config.enabled) return;
      scanDocument(document);
    })
  );

  // Clear diagnostics on document close
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((document) => {
      diagnosticCollection.delete(document.uri);
    })
  );

  // Re-create engine when config changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("bulkhead")) {
        engine.dispose();
        engine = createEngine();
        for (const editor of vscode.window.visibleTextEditors) {
          scanDocument(editor.document);
        }
      }
    })
  );

  // Status bar
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBar.text = "$(shield) Bulkhead";
  statusBar.tooltip = "Bulkhead guardrails active";
  statusBar.command = "bulkhead.scanFile";
  statusBar.show();
  context.subscriptions.push(statusBar);

  // Scan currently open documents
  for (const editor of vscode.window.visibleTextEditors) {
    scanDocument(editor.document);
  }
}

function createEngine(): GuardrailsEngine {
  const config = getConfig();
  const newEngine = new GuardrailsEngine();

  if (config.guards.pii.enabled) {
    newEngine.addGuard(new PiiGuard());
  }
  if (config.guards.secret.enabled) {
    newEngine.addGuard(new SecretGuard());
  }
  if (config.guards.injection.enabled) {
    newEngine.addGuard(new InjectionGuard());
    newEngine.addGuard(new LeakageGuard());
  }

  // Initialize cascade for deep scan (BERT + LLM layers)
  if (config.cascade.modelEnabled) {
    newEngine.initCascade({
      bertEnabled: true,
      llmEnabled: config.guards.contentSafety.enabled,
      escalationThreshold: config.cascade.escalationThreshold,
      contextSentences: config.cascade.contextSentences,
      modelId: config.cascade.modelId,
    });
  }

  return newEngine;
}

/** Auto-scan uses regex-only path (Layer 1) — always fast */
async function scanDocument(document: vscode.TextDocument): Promise<void> {
  if (document.uri.scheme !== "file") return;

  const text = document.getText();
  if (text.length === 0) return;

  try {
    const results = await engine.analyze(text);
    const diagnostics = resultsToDiagnostics(document, results);
    diagnosticCollection.set(document.uri, diagnostics);
  } catch {
    // Silently fail — don't disrupt the user
  }
}

export function deactivate(): void {
  if (debounceTimer) clearTimeout(debounceTimer);
  engine?.dispose();
}
