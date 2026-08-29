import * as vscode from "vscode";

/**
 * Barre de statut Nialame. Ne bloque jamais l'éditeur : affiche
 * uniquement un état "Analysing…" / compteur de findings, jamais de
 * squiggle ou de diagnostic intrusif (voir contraintes UX du produit).
 */
export class StatusBarProvider {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = "nialame.openChat";
    this.setIdle();
    this.item.show();
  }

  setIdle(): void {
    this.item.text = "$(shield) Nialame";
    this.item.tooltip = "Nialame AI — inactif";
  }

  setAnalyzing(): void {
    this.item.text = "$(sync~spin) Nialame: Analysing…";
    this.item.tooltip = "Nialame AI analyse le fichier courant";
  }

  setFindingsCount(count: number): void {
    if (count === 0) {
      this.item.text = "$(shield) Nialame";
      this.item.tooltip = "Nialame AI — aucun problème détecté";
      return;
    }
    this.item.text = `$(warning) Nialame: ${count}`;
    this.item.tooltip = `Nialame AI — ${count} finding(s) détecté(s)`;
  }

  dispose(): void {
    this.item.dispose();
  }
}
