import * as vscode from "vscode";
import { WorkspaceScanner } from "../services/workspaceScanner";

export function registerScanWorkspaceCommand(scanner: WorkspaceScanner): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.scanWorkspace", async () => {
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Nialame: analyse du workspace",
        cancellable: false,
      },
      async (progress) => {
        const results = await scanner.scanWorkspace(progress);
        const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);

        if (totalFindings === 0) {
          vscode.window.showInformationMessage("Nialame: aucun problème détecté dans le workspace.");
          return;
        }

        const choice = await vscode.window.showWarningMessage(
          `Nialame: ${totalFindings} finding(s) détecté(s) dans ${results.length} fichier(s).`,
          "Ouvrir le chat"
        );
        if (choice === "Ouvrir le chat") {
          await vscode.commands.executeCommand("nialame.openChat");
        }
      }
    );
  });
}
