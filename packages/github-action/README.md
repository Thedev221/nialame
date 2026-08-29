# GitHub Action — Nialame Security Scan

Scanne les fichiers Python d'un dépôt avec le moteur Tier 1 déterministe du Core Engine et publie un rapport SARIF.

## Usage

```yaml
name: Nialame Security Scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  nialame:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@FULL_COMMIT_SHA
      - uses: nialame/nialame-action@FULL_COMMIT_SHA
        id: scan
        with:
          fail-on: critical
          upload-sarif: true
          llm-enabled: false
      - uses: github/codeql-action/upload-sarif@FULL_COMMIT_SHA
        if: always()
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-path }}
```

## Entrées

| Nom | Défaut | Description |
|---|---|---|
| `fail-on` | `critical` | Sévérité minimale qui fait échouer le job (`critical`, `high`, `medium`, `low`, `info`, `none`). |
| `upload-sarif` | `true` | Indicatif pour le workflow appelant (l'upload effectif se fait via `codeql-action/upload-sarif`). |
| `llm-enabled` | `false` | Réservé pour une future activation du Tier 2 en CI — non câblé dans ce MVP. |
| `paths` | `**/*.py` | Glob des fichiers à analyser. |

## Garanties de sécurité

- Aucun code source n'est écrit dans les logs (seuls chemins de fichiers et compteurs).
- Le LLM n'est jamais appelé, quelle que soit la valeur de `llm-enabled`, tant que le câblage CI n'est pas livré.
- Permissions minimales requises : `contents: read`, `security-events: write` si upload SARIF.
