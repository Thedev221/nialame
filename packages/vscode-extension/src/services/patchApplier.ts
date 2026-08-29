import * as vscode from "vscode";
import { CoreApiClient } from "./coreApiClient";
import { fingerprintDocument, matchesFingerprint } from "./documentHasher";
import { SuggestedPatch } from "../types/api";

export class PatchRejectedError extends Error {}

/**
 * Applique un patch proposé, en respectant strictement la séquence :
 * 1. vérification version/hash face au document ouvert ;
 * 2. prévisualisation diff native ;
 * 3. confirmation explicite de l'utilisateur ;
 * 4. application via WorkspaceEdit ;
 * 5. notification de succès/échec ;
 * 6. nouveau scan du fichier (délégué à l'appelant).
 *
 * Le patch n'est JAMAIS appliqué sans confirmation, et JAMAIS si le
 * document a changé depuis l'analyse qui l'a produit.
 */
export class PatchApplier {
  constructor(private readonly apiClient: CoreApiClient) {}

  async previewAndApply(document: vscode.TextDocument, patch: SuggestedPatch): Promise<boolean> {
    const currentFingerprint = fingerprintDocument(document);

    if (
      currentFingerprint.sha256 !== patch.document_sha256 ||
      currentFingerprint.version !== patch.document_version
    ) {
      vscode.window.showWarningMessage(
        "Nialame: ce patch a été calculé sur une version antérieure du fichier. " +
          "Relancez un scan pour obtenir un patch à jour."
      );
      return false;
    }

    const validation = await this.apiClient.validatePatch(
      {
        uri: currentFingerprint.uri,
        version: currentFingerprint.version,
        sha256: currentFingerprint.sha256,
        content: document.getText(),
      },
      patch
    );

    if (!validation.valid) {
      vscode.window.showErrorMessage(
        `Nialame: patch refusé — ${validation.reasons.join(" ")}`
      );
      return false;
    }

    const proceed = await this.showDiffPreview(document, patch);
    if (!proceed) {
      return false;
    }

    // Re-vérifier juste avant l'écriture : le document a pu changer
    // pendant que l'utilisateur regardait la prévisualisation.
    if (!matchesFingerprint(document, currentFingerprint)) {
      vscode.window.showWarningMessage(
        "Nialame: le document a changé pendant la prévisualisation. Patch annulé."
      );
      return false;
    }

    const applied = await this.applyViaWorkspaceEdit(document, patch);
    if (applied) {
      vscode.window.showInformationMessage("Nialame: patch appliqué. Relance du scan…");
    } else {
      vscode.window.showErrorMessage("Nialame: échec de l'application du patch.");
    }
    return applied;
  }

  private async showDiffPreview(document: vscode.TextDocument, patch: SuggestedPatch): Promise<boolean> {
    const originalUri = document.uri;
    const patchedContent = this.applyRangeReplacement(document, patch);

    const patchedDocument = await vscode.workspace.openTextDocument({
      language: document.languageId,
      content: patchedContent,
    });

    await vscode.commands.executeCommand(
      "vscode.diff",
      originalUri,
      patchedDocument.uri,
      `Nialame — prévisualisation du patch (${patch.finding_rule_id})`
    );

    const choice = await vscode.window.showInformationMessage(
      `Appliquer le patch pour ${patch.finding_rule_id} ? Cette action ne peut pas être annulée automatiquement.`,
      { modal: true },
      "Appliquer",
      "Annuler"
    );

    return choice === "Appliquer";
  }

  private applyRangeReplacement(document: vscode.TextDocument, patch: SuggestedPatch): string {
    const replacementLines = patch.unified_diff
      .split("\n")
      .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
      .map((line) => line.slice(1));

    const startLine = patch.anchor_range.start_line - 1;
    const endLine = patch.anchor_range.end_line;

    const lines = document.getText().split("\n");
    const newLines = [...lines.slice(0, startLine), ...replacementLines, ...lines.slice(endLine)];
    return newLines.join("\n");
  }

  private async applyViaWorkspaceEdit(document: vscode.TextDocument, patch: SuggestedPatch): Promise<boolean> {
    const edit = new vscode.WorkspaceEdit();
    const range = new vscode.Range(
      new vscode.Position(patch.anchor_range.start_line - 1, 0),
      new vscode.Position(patch.anchor_range.end_line, 0)
    );

    const replacementLines = patch.unified_diff
      .split("\n")
      .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
      .map((line) => line.slice(1))
      .join("\n");

    edit.replace(document.uri, range, replacementLines + "\n");
    return vscode.workspace.applyEdit(edit);
  }
}
