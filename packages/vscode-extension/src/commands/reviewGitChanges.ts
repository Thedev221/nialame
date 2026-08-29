import * as vscode from "vscode";
import { GitService } from "../git/gitService";
import { extractChangedPythonFiles } from "../git/diffParser";
import { CoreApiClient } from "../services/coreApiClient";

export function registerReviewGitChangesCommand(
  gitService: GitService,
  apiClient: CoreApiClient
): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.reviewGitChanges", async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showInformationMessage("Nialame: aucun dossier de travail ouvert.");
      return;
    }

    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: "Nialame: revue des changements Git" },
      async () => {
        try {
          const diff = await gitService.getWorkingTreeDiff(folder.uri.fsPath);
          if (!diff.trim()) {
            vscode.window.showInformationMessage("Nialame: aucun changement Git détecté.");
            return;
          }

          const changedFiles = extractChangedPythonFiles(diff);
          const review = await apiClient.reviewGitDiff(diff, changedFiles);

          const totalFindings = review.results.reduce((sum, r) => sum + r.findings.length, 0);
          if (totalFindings === 0) {
            vscode.window.showInformationMessage("Nialame: aucun problème détecté dans les changements Git.");
            return;
          }

          const choice = await vscode.window.showWarningMessage(
            `Nialame: ${totalFindings} finding(s) dans les changements Git non commités.`,
            "Ouvrir le chat"
          );
          if (choice === "Ouvrir le chat") {
            await vscode.commands.executeCommand("nialame.openChat");
          }
        } catch (err) {
          vscode.window.showErrorMessage(`Nialame: échec de la revue Git — ${String(err)}`);
        }
      }
    );
  });
}
