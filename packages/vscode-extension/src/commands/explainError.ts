import * as vscode from "vscode";
import { randomUUID } from "crypto";
import { NialameViewProvider } from "../providers/nialameViewProvider";

/**
 * Explique la ligne courante en mode "debug", en s'appuyant sur les
 * diagnostics existants (linters, pyright, etc.) présents à la position
 * du curseur, sans dupliquer leur logique.
 */
export function registerExplainErrorCommand(provider: NialameViewProvider): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.explainError", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage("Nialame: aucun fichier actif.");
      return;
    }

    const diagnostics = vscode.languages
      .getDiagnostics(editor.document.uri)
      .filter((d) => d.range.contains(editor.selection.active));

    if (diagnostics.length === 0) {
      vscode.window.showInformationMessage("Nialame: aucune erreur détectée à la position du curseur.");
      return;
    }

    const messages = diagnostics.map((d) => `- ${d.message}`).join("\n");

    provider.reveal();
    await provider.sendChatMessage(
      randomUUID(),
      "debug",
      "selection",
      `Explique cette erreur et propose une piste de correction :\n${messages}`
    );
  });
}
