# Guide — Création de la GitHub App

## Étapes

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
2. Renseigner l'URL de webhook : `https://<votre-domaine>/webhooks/github`.
3. Générer un secret de webhook fort et le placer dans `GITHUB_WEBHOOK_SECRET`.
4. Permissions à sélectionner (voir justification dans `packages/github-app/README.md`) :
   - Contents: Read-only
   - Pull requests: Read-only
   - Checks: Write
   - Metadata: Read-only (par défaut)
5. Événements à souscrire : `pull_request`, `push` (optionnel), `installation`, `installation_repositories`.
6. Générer une clé privée (.pem), la stocker de façon sécurisée, référencer son chemin via `GITHUB_APP_PRIVATE_KEY_PATH`.
7. Noter l'App ID, le placer dans `GITHUB_APP_ID`.

## Ne jamais faire

- Ne pas cocher "Write" sur Contents.
- Ne pas cocher Administration ou Actions.
- Ne pas activer les commentaires inline (`NIALAME_ENABLE_INLINE_COMMENTS`) sans revue préalable de la politique de l'organisation.
