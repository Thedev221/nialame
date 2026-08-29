import * as vscode from "vscode";
import { NialameViewProvider } from "../providers/nialameViewProvider";

export function registerOpenChatCommand(provider: NialameViewProvider): vscode.Disposable {
  return vscode.commands.registerCommand("nialame.openChat", () => {
    provider.reveal();
  });
}
