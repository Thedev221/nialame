import * as vscode from "vscode";
import { CoreApiClient } from "./services/coreApiClient";
import { RequestManager } from "./services/requestManager";
import { WorkspaceScanner } from "./services/workspaceScanner";
import { PatchApplier } from "./services/patchApplier";
import { getSettings, onSettingsChanged } from "./services/settings";
import { NialameViewProvider } from "./providers/nialameViewProvider";
import { StatusBarProvider } from "./providers/statusBarProvider";
import { GitService } from "./git/gitService";

import { registerOpenChatCommand } from "./commands/openChat";
import { registerOpenSettingsCommand } from "./commands/openSettings";
import { registerScanCurrentFileCommand, registerScanOnSave } from "./commands/scanCurrentFile";
import { registerScanWorkspaceCommand } from "./commands/scanWorkspace";
import { registerExplainSelectionCommand } from "./commands/explainSelection";
import { registerExplainErrorCommand } from "./commands/explainError";
import { registerFixFindingCommand } from "./commands/fixFinding";
import { registerReviewGitChangesCommand } from "./commands/reviewGitChanges";

export function activate(context: vscode.ExtensionContext): void {
  const apiClient = new CoreApiClient();
  const requestManager = new RequestManager();
  const statusBar = new StatusBarProvider();
  const patchApplier = new PatchApplier(apiClient);
  const workspaceScanner = new WorkspaceScanner(apiClient);
  const gitService = new GitService();

    const viewProvider = new NialameViewProvider(context.extensionUri, apiClient, patchApplier);

  void gitService.initialize();

  const onFindings = (_documentUri: string, findings: unknown[]) => {
    statusBar.setFindingsCount(findings.length);
  };

  context.subscriptions.push(
    statusBar,
    vscode.window.registerWebviewViewProvider(NialameViewProvider.viewType, viewProvider),
    registerOpenChatCommand(viewProvider),
    registerOpenSettingsCommand(),
    registerScanCurrentFileCommand(apiClient, requestManager, statusBar, onFindings),
    registerScanWorkspaceCommand(workspaceScanner),
    registerExplainSelectionCommand(viewProvider),
    registerExplainErrorCommand(viewProvider),
    registerFixFindingCommand(apiClient, patchApplier),
    registerReviewGitChangesCommand(gitService, apiClient),
    registerScanOnSave(
      apiClient,
      requestManager,
      statusBar,
      onFindings,
      getSettings().scanOnSaveDebounceMs
    ),
    onSettingsChanged(() => {
      // Les services relisent la configuration à chaque appel
      // (voir getSettings()) : rien à recâbler ici.
    })
  );
}

export function deactivate(): void {
  // Aucune ressource persistante à nettoyer explicitement : toutes les
  // Disposable sont gérées via context.subscriptions.
}
