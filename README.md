# Nialame AI

Plateforme de sécurité applicative intégrée à VS Code et GitHub. Analyse déterministe (AST) en temps réel, chat contextuel assisté par LLM optionnel, revue de pull requests automatisée.

## Principes non négociables

1. Le développeur garde toujours le contrôle : aucun patch n'est appliqué sans validation humaine explicite.
2. Le LLM est consultatif et non fiable — désactivé par défaut, aucun accès shell/Git/réseau/secrets.
3. Le scan déterministe (Tier 1, AST) fonctionne même LLM désactivé.
4. Permissions GitHub minimales, lecture seule par défaut.
5. Aucun push automatique, aucune création de branche.

## Architecture

Monorepo à quatre packages, tous clients du **Core Engine** (Python/FastAPI), source de vérité pour l'analyse AST, la redaction, la génération de patch et de SARIF.

```
packages/
├── core-engine/       # FastAPI — moteur d'analyse Tier 1 (AST) + Tier 2 (LLM optionnel)
├── vscode-extension/  # Extension VS Code TypeScript — chat, scan, application de patch
├── github-action/     # Action Docker — scan CI déterministe, SARIF
└── github-app/        # App GitHub FastAPI — webhooks, check runs, résumé de PR
```

## Installation rapide

Voir `docs/architecture.md` pour le détail. En résumé :

```bash
# Core Engine
cd packages/core-engine
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
uvicorn nialame.main:app --reload --host 127.0.0.1 --port 8000

# Extension VS Code
cd packages/vscode-extension
npm install
npm run compile
# F5 dans VS Code pour lancer l'Extension Development Host
```

## Limitations connues (MVP)

- Un seul langage analysé en profondeur : Python (`ast`). Tree-sitter multi-langage est prévu mais non livré.
- Aucun outil agentique, aucune exécution de code par le LLM.
- La GitHub App ne crée ni branche ni pull request corrective.
- Nialame ne remplace pas un audit de sécurité ni un test d'intrusion — voir `docs/privacy.md` et `docs/threat-model.md`.

## Licence

Voir `LICENSE`.
