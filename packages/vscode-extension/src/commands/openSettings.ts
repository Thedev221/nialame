import * as vscode from "vscode";
import { openSettingsUi } from "../services/settings";

export function registerOpenSettingsCommand(): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.openSettings", async () => {
    await openSettingsUi();
  });
}
