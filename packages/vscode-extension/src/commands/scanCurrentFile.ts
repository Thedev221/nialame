import * as vscode from "vscode";
import { CoreApiClient } from "../services/coreApiClient";
import { fingerprintDocument } from "../services/documentHasher";
import { RequestManager } from "../services/requestManager";
import { StatusBarProvider } from "../providers/statusBarProvider";
import { Finding } from "../types/api";

export type FindingsListener = (documentUri: string, findings: Finding[]) => void;

/**
 * Scanne le fichier actif. Ne bloque jamais l'UI : lancé en tâche de
 * fond, résultat ignoré si le document a changé entre-temps.
 */
export async function scanDocument(
  document: vscode.TextDocument,
  apiClient: CoreApiClient,
  requestManager: RequestManager,
  statusBar: StatusBarProvider,
  onFindings: FindingsListener
): Promise<void> {
  if (document.languageId !== "python") {
    return;
  }

  const { requestId, signal } = requestManager.beginRequest(document.uri.toString(), document.version);
  statusBar.setAnalyzing();

  try {
    const fingerprint = fingerprintDocument(document);
    const response = await apiClient.scan(
      { ...fingerprint, content: document.getText() },
      signal
    );

    if (!requestManager.isStillRelevant(requestId)) {
      return;
    }

    statusBar.setFindingsCount(response.findings.length);
    onFindings(document.uri.toString(), response.findings);
  } catch (err) {
    if ((err as { name?: string }).name !== "AbortError") {
      vscode.window.showErrorMessage(`Nialame: échec du scan — ${String(err)}`);
    }
    statusBar.setIdle();
  } finally {
    requestManager.complete(requestId);
  }
}

export function registerScanCurrentFileCommand(
  apiClient: CoreApiClient,
  requestManager: RequestManager,
  statusBar: StatusBarProvider,
  onFindings: FindingsListener
): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.scanCurrentFile", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage("Nialame: aucun fichier actif à analyser.");
      return;
    }
    await scanDocument(editor.document, apiClient, requestManager, statusBar, onFindings);
  });
}

/**
 * Attache un scan automatique après sauvegarde, avec debounce et
 * annulation des requêtes précédentes pour le même document.
 */
export function registerScanOnSave(
  apiClient: CoreApiClient,
  requestManager: RequestManager,
  statusBar: StatusBarProvider,
  onFindings: FindingsListener,
  debounceMs: number
): vscode.Disposable {
  const timers = new Map<string, ReturnType<typeof setTimeout>>();

  return vscode.workspace.onDidSaveTextDocument((document) => {
    if (document.languageId !== "python") {
      return;
    }
    const key = document.uri.toString();

    const existing = timers.get(key);
    if (existing) {
      clearTimeout(existing);
    }
    requestManager.cancelAllForDocument(key);

    const timer = setTimeout(() => {
      timers.delete(key);
      void scanDocument(document, apiClient, requestManager, statusBar, onFindings);
    }, debounceMs);

    timers.set(key, timer);
  });
}
