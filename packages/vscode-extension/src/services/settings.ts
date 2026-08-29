import * as vscode from "vscode";

export interface NialameSettings {
  coreEngineUrl: string;
  allowLlm: boolean;
  scanOnSaveDebounceMs: number;
}

const SECTION = "nialame";

export function getSettings(): NialameSettings {
  const config = vscode.workspace.getConfiguration(SECTION);
  return {
    coreEngineUrl: config.get<string>("coreEngineUrl", "http://127.0.0.1:8000"),
    allowLlm: config.get<boolean>("allowLlm", false),
    scanOnSaveDebounceMs: config.get<number>("scanOnSaveDebounceMs", 800),
  };
}

export function onSettingsChanged(listener: () => void): vscode.Disposable {
  return vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration(SECTION)) {
      listener();
    }
  });
}

export function openSettingsUi(): Thenable<void> {
  return vscode.commands.executeCommand("workbench.action.openSettings", `@ext:nialame.nialame-ai`);
}
