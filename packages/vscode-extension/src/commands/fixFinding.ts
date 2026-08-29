import * as vscode from "vscode";
import { CoreApiClient } from "../services/coreApiClient";
import { PatchApplier } from "../services/patchApplier";
import { fingerprintDocument } from "../services/documentHasher";

/**
 * Demande un patch pour un finding donné (mode "fix"), puis délègue
 * systématiquement à PatchApplier pour la prévisualisation et la
 * confirmation — jamais d'application directe depuis cette commande.
 */
export function registerFixFindingCommand(
  apiClient: CoreApiClient,
  patchApplier: PatchApplier
): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.fixFinding", async (ruleId?: string) => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage("Nialame: aucun fichier actif.");
      return;
    }
    if (!ruleId) {
      vscode.window.showInformationMessage(
        "Nialame: sélectionnez un finding depuis le panneau de chat pour proposer un correctif."
      );
      return;
    }

    const document = editor.document;
    const fingerprint = fingerprintDocument(document);

    const chatResponse = await apiClient.chat({
      mode: "fix",
      scope: "current_file",
      message: `Propose un patch pour corriger le finding ${ruleId}.`,
      language: "python",
      document: { ...fingerprint, content: document.getText() },
    });

    const patch = chatResponse.suggested_patches.find((p) => p.finding_rule_id === ruleId);
    if (!patch) {
      vscode.window.showInformationMessage(
        "Nialame: aucun patch n'a pu être généré pour ce finding (LLM désactivé ou analyse insuffisante)."
      );
      return;
    }

    await patchApplier.previewAndApply(document, patch);
  });
}
