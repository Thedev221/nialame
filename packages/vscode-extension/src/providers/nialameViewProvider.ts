import * as vscode from "vscode";
import { buildWebviewHtml } from "../webview/html";
import { parseWebviewMessage, InvalidWebviewMessageError } from "../webview/messages";
import { CoreApiClient } from "../services/coreApiClient";
import { RequestManager } from "../services/requestManager";
import { PatchApplier } from "../services/patchApplier";
import { fingerprintDocument } from "../services/documentHasher";
import { getSettings } from "../services/settings";
import { ExtensionToWebviewMessage } from "../types/ui";
import { ChatRequest } from "../types/api";

export class NialameViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "nialame.chatView";

  private view: vscode.WebviewView | undefined;
  private readonly requestManager = new RequestManager();

  constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly apiClient: CoreApiClient,
    private readonly patchApplier: PatchApplier
  ) {}

  resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, "media")],
    };
    webviewView.webview.html = buildWebviewHtml(webviewView.webview, this.extensionUri);

    webviewView.webview.onDidReceiveMessage(async (raw) => {
      try {
        const message = parseWebviewMessage(raw);
        await this.handleMessage(message);
      } catch (err) {
        if (err instanceof InvalidWebviewMessageError) {
          console.warn(err.message);
          return;
        }
        throw err;
      }
    });

    this.postPrivacyStatus();
  }

  private postPrivacyStatus(): void {
    const { allowLlm } = getSettings();
    this.post({
      type: "privacyStatus",
      localMode: true,
      provider: allowLlm ? "ollama" : null,
      llmEnabled: allowLlm,
    });
  }

  private async handleMessage(
    message: ReturnType<typeof parseWebviewMessage>
  ): Promise<void> {
    switch (message.command) {
      case "sendChatMessage":
        await this.sendChatMessage(message.requestId, message.mode, message.scope, message.message);
        return;
      case "openLocation":
        this.openLocation(message.line, message.column);
        return;
      case "explainWhy":
        await this.sendChatMessage(
          `explain-${message.ruleId}-${Date.now()}`,
          "explain",
          "current_file",
          `Explique en détail pourquoi le finding ${message.ruleId} est un risque de sécurité et comment un attaquant pourrait l'exploiter.`
        );
        return;
      case "markFalsePositive":
        vscode.window.showInformationMessage(
          `Nialame: ${message.ruleId} marqué comme faux positif pour cette session. ` +
            "La suppression persistante par règle sera ajoutée dans une future version."
        );
        return;
      case "ignoreRuleInFile":
        vscode.window.showInformationMessage(
          `Nialame: ${message.ruleId} ignoré dans ce fichier pour cette session.`
        );
        return;
      case "applyPatch":
      case "previewDiff":
        vscode.window.showInformationMessage(
          "Nialame: utilisez la commande 'Nialame: Fix Selected Finding' pour appliquer un patch — " +
            "cette action nécessite le Tier 2 (LLM) pour générer un correctif."
        );
        return;
      case "copyToClipboard":
        await vscode.env.clipboard.writeText(message.text);
        return;
      case "retry":
        return;
      default:
        return;
    }
  }

  private openLocation(line: number, column: number): void {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage("Nialame: aucun éditeur actif pour naviguer vers cette position.");
      return;
    }
    const position = new vscode.Position(Math.max(line - 1, 0), Math.max(column, 0));
    editor.selection = new vscode.Selection(position, position);
    editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
  }

  async sendChatMessage(
    requestId: string,
    mode: ChatRequest["mode"],
    scope: ChatRequest["scope"],
    text: string
  ): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    const document = editor?.document;

    const { requestId: internalId, signal } = this.requestManager.beginRequest(
      document?.uri.toString() ?? "no-document",
      document?.version ?? 0
    );

    this.post({ type: "scanStarted", requestId });

    try {
      const selection = editor?.selection;
      const chatRequest: ChatRequest = {
        mode,
        scope,
        message: text,
        language: "python",
        document: document
          ? {
              ...fingerprintDocument(document),
              content: document.getText(),
            }
          : undefined,
        selection:
          selection && document
            ? {
                start_line: selection.start.line + 1,
                start_column: selection.start.character,
                end_line: selection.end.line + 1,
                end_column: selection.end.character,
              }
            : undefined,
      };

      const response = await this.apiClient.chat(chatRequest, signal);

      if (!this.requestManager.isStillRelevant(internalId)) {
        return;
      }

      this.post({
        type: "chatResponse",
        requestId,
        answerMarkdown: response.answer_markdown,
        findings: response.findings,
        patches: response.suggested_patches,
        warnings: response.warnings,
        privacy: { llmUsed: response.privacy.llm_used, provider: response.privacy.provider },
      });

      // Si le mode "fix" a produit un patch, on déclenche immédiatement
      // la prévisualisation diff + confirmation, plutôt que de laisser
      // le patch invisible dans les données de la réponse.
      if (mode === "fix" && document && response.suggested_patches.length > 0) {
        await this.patchApplier.previewAndApply(document, response.suggested_patches[0]);
      }
    } catch (err) {
      this.post({ type: "chatError", requestId, message: String(err) });
    } finally {
      this.requestManager.complete(internalId);
    }
  }

  private post(message: ExtensionToWebviewMessage): void {
    this.view?.webview.postMessage(message);
  }

  reveal(): void {
    this.view?.show?.(true);
  }
}
