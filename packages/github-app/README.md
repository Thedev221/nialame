# GitHub App — Nialame AI

Service FastAPI qui reçoit les webhooks GitHub, analyse les pull requests via le Core Engine, et publie un résumé de sécurité (check run) — jamais de commit, push ou création de branche.

## Endpoints

- `GET /health`
- `POST /webhooks/github`
- `GET /install`
- `GET /callback`

## Permissions GitHub minimales (à configurer sur la App)

| Permission | Niveau | Justification |
|---|---|---|
| Contents | Read-only | Lire les fichiers modifiés dans une PR. |
| Pull requests | Read-only | Lire les métadonnées et le diff de la PR. |
| Checks | Write | Publier le résultat de scan sous forme de check run. |
| Metadata | Read-only | Requis par défaut par toute GitHub App. |

Aucune autre permission n'est nécessaire pour le MVP. Aucun accès aux secrets, à Actions, à Administration, ni écriture sur le contenu du dépôt.

## Webhooks

- `pull_request`
- `push` (uniquement si le scan de branche est explicitement configuré)
- `installation`
- `installation_repositories`

Chaque requête webhook est validée par signature HMAC (`X-Hub-Signature-256`). Toute requête sans signature valide est rejetée avec 401. La déduplication des `delivery_id` empêche le traitement en double d'un même événement rejoué (fenêtre configurable via `NIALAME_WEBHOOK_DEDUP_TTL_SECONDS`).

## Lancer en local

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
uvicorn nialame_github_app.main:app --host 127.0.0.1 --port 8080
```
