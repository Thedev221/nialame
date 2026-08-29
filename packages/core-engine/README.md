# Core Engine

Backend FastAPI, source de vérité pour l'analyse de sécurité de Nialame AI.

## Endpoints

- `GET /health`
- `POST /api/v1/scan`
- `POST /api/v1/chat`
- `POST /api/v1/review/git-diff`
- `POST /api/v1/review/repository`
- `POST /api/v1/patch/validate`
- `POST /api/v1/sarif`

## Lancer en local

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
uvicorn nialame.main:app --reload --host 127.0.0.1 --port 8000
```

## Tests

```bash
pytest -v
```

## Pipeline d'analyse (résumé)

1. Validation de la requête (Pydantic).
2. Vérification SHA-256 du document.
3. Limite de taille.
4. Analyse Tier 1 déterministe (`ast`).
5. Recherche du symbole AST englobant pour chaque finding.
6. Redaction AST-aware + regex avant tout envoi LLM.
7. Extraction de contexte minimal.
8. Appel LLM (Tier 2) seulement si `NIALAME_LLM_ENABLED=true` et autorisé par la requête.
9. Validation stricte de la sortie JSON du LLM (Pydantic).
10. Ancrage du patch à un hash + version + plage de lignes.
11. Remplacement en mémoire du seul bloc autorisé.
12. Validation syntaxique du patch (`ast.parse`).
13. Re-scan du résultat.
14. Détection de régression (nouvelles alertes égales ou plus graves).
15. Génération d'un unified diff (`difflib`).
16. Réponse avec `human_review_required=true`.
