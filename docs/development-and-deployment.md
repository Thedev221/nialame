# Guide de développement local, configuration LLM et CI/CD

## Développement local — vue d'ensemble

```bash
# 1. Core Engine
cd packages/core-engine
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
pytest -v
uvicorn nialame.main:app --reload --host 127.0.0.1 --port 8000

# 2. Extension VS Code (autre terminal)
cd packages/vscode-extension
npm install
npm run compile
# F5 dans VS Code

# 3. GitHub App (optionnel, autre terminal)
cd packages/github-app
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
pytest -v
uvicorn nialame_github_app.main:app --host 127.0.0.1 --port 8080
```

## Configuration Ollama (LLM local, Tier 2)

1. Installer Ollama : https://ollama.com
2. `ollama pull qwen2.5-coder:7b` (ou un autre modèle de code).
3. Dans `packages/core-engine/.env` :
   ```
   NIALAME_LLM_ENABLED=true
   NIALAME_LLM_PROVIDER=ollama
   NIALAME_LLM_BASE_URL=http://127.0.0.1:11434
   NIALAME_LLM_MODEL=qwen2.5-coder:7b
   ```
4. Redémarrer le Core Engine.

## Configuration provider cloud (BYOK)

Non câblé dans ce MVP (`llm.py` ne supporte que `ollama`). Pour l'ajouter : implémenter un nouveau provider dans `nialame/llm.py` respectant la même interface (`analyze_with_llm`), avec la clé API lue uniquement côté serveur (jamais transmise par l'extension ou la Webview).

## CI/CD

Voir `examples/github-workflow.yml` pour un pipeline GitHub Actions complet : scan sur chaque pull request, upload SARIF, échec du job sur `fail-on: critical`.

Pour publier une nouvelle version :
1. Core Engine : bump `version` dans `pyproject.toml`, tag Git, build/push l'image Docker.
2. Extension VS Code : bump `version` dans `package.json`, `vsce publish`.
3. GitHub Action : tag Git épinglé par SHA complet dans les workflows consommateurs.
4. GitHub App : redéployer le service FastAPI (ex. conteneur derrière un reverse proxy TLS).
