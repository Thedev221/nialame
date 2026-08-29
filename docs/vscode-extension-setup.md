# Guide — Extension VS Code

## Prérequis

- Node.js 20+, npm.
- Core Engine lancé en local sur `http://127.0.0.1:8000` (voir guide Core Engine).

## Installation en mode développement

```bash
cd packages/vscode-extension
npm install
npm run compile
```

Puis ouvrir le dossier `packages/vscode-extension` dans VS Code et appuyer sur `F5` pour lancer l'Extension Development Host.

## Configuration

Dans les paramètres VS Code (`Nialame: Open Settings`) :

- `nialame.coreEngineUrl` — URL du Core Engine (défaut `http://127.0.0.1:8000`).
- `nialame.allowLlm` — active le Tier 2 (défaut `false`).
- `nialame.scanOnSaveDebounceMs` — délai avant scan après sauvegarde (défaut `800`).

## Publication sur le VS Code Marketplace

1. Créer un éditeur (`publisher`) sur https://marketplace.visualstudio.com/manage.
2. `npm install -g @vscode/vsce`
3. `vsce package` pour générer le `.vsix`.
4. `vsce publish` (nécessite un Personal Access Token Azure DevOps).
