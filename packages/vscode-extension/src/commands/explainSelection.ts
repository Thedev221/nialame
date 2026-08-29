import * as vscode from "vscode";
import { NialameViewProvider } from "../providers/nialameViewProvider";
import { randomUUID } from "crypto";

export function registerExplainSelectionCommand(provider: NialameViewProvider): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.explainSelection", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.selection.isEmpty) {
      vscode.window.showInformationMessage("Nialame: sélectionnez du code à expliquer.");
      return;
    }

    provider.reveal();
    await provider.sendChatMessage(
      randomUUID(),
      "explain",
      "selection",
      "Explique ce que fait ce code et signale tout risque de sécurité potentiel."
    );
  });
}
