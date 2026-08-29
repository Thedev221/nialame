# Politique de confidentialité

## Ce qui n'est jamais envoyé nulle part

- Aucun code source n'est stocké de façon persistante par le Core Engine par défaut.
- Aucun secret ou code source n'apparaît dans les logs applicatifs (logs structurés, sans prompt ni réponse LLM brute).

## Ce qui est envoyé au LLM (Tier 2), et seulement si activé

Le LLM est **désactivé par défaut** (`NIALAME_LLM_ENABLED=false`). Quand il est activé :

- Seul le fragment de code entourant un finding Tier 1 est envoyé, pas le fichier entier ni le dépôt.
- Une redaction regex + AST-aware est appliquée avant l'envoi (secrets connus, variables nommées `password`/`token`/`api_key`/etc.).
- Le provider par défaut est Ollama, **local** — rien ne sort de la machine de l'utilisateur.
- Un provider cloud (BYOK) n'est utilisé que si explicitement configuré côté serveur ; jamais de clé API transmise depuis la Webview ou le client.

## Ce qui est envoyé à GitHub (GitHub App / Action)

- Lecture seule des fichiers modifiés dans une pull request.
- Publication d'un résumé de sécurité (check run) — pas de code source dans le résumé, uniquement des noms de fichiers, règles et messages.
- Aucune écriture sur le contenu du dépôt, aucun commentaire inline par défaut.

## Comment désactiver totalement le LLM

Laisser `NIALAME_LLM_ENABLED=false` (valeur par défaut) dans `.env` du Core Engine, et `nialame.allowLlm: false` (valeur par défaut) dans les paramètres VS Code.

## Comment exécuter l'outil uniquement en local

Le Core Engine est lié à `127.0.0.1` par défaut. Ne jamais changer `NIALAME_HOST` vers `0.0.0.0` sans ajouter TLS, authentification, CORS strict et rate limiting.
