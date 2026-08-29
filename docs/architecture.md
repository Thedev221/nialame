# Architecture

## Vue d'ensemble

Nialame AI est un monorepo à quatre packages, tous clients d'un unique **Core Engine** Python/FastAPI qui reste la source de vérité pour l'analyse AST, la redaction, la génération de patch et de SARIF.

```
┌─────────────────┐     ┌──────────────────┐
│ VS Code          │────▶│                  │
│ Extension (TS)   │     │                  │
└─────────────────┘     │   Core Engine     │
                         │   (FastAPI,       │
┌─────────────────┐     │   Python 3.12+)   │
│ GitHub Action     │────▶│                  │
│ (Docker, CLI)     │     │                  │
└─────────────────┘     └──────────────────┘
                                  ▲
┌─────────────────┐             │
│ GitHub App        │─────────────┘
│ (FastAPI, webhooks)│
└─────────────────┘
```

## Pourquoi un seul moteur d'analyse

Dupliquer la logique AST en TypeScript et en Python créerait deux sources de vérité divergentes : un finding détecté dans l'IDE pourrait différer d'un finding détecté en CI. Toutes les surfaces appellent donc le même Core Engine :

- l'extension VS Code via HTTP local (`http://127.0.0.1:8000`) ;
- la GitHub Action via installation du package Python directement dans son image Docker ;
- la GitHub App via appel HTTP au Core Engine (déployé à côté, ou en tant que dépendance embarquée selon le déploiement).

## Flux de données — scan IDE

1. L'utilisateur sauvegarde un fichier Python.
2. L'extension calcule le SHA-256 du contenu et envoie `document.version`, `document.sha256`, `document.content` à `POST /api/v1/scan`.
3. Le Core Engine exécute le Tier 1 (AST), retourne les findings.
4. L'extension affiche les findings dans le panneau webview et met à jour la barre de statut — jamais de diagnostic intrusif dans l'éditeur.

## Flux de données — pull request GitHub

1. GitHub envoie un webhook `pull_request` à la GitHub App.
2. Signature HMAC vérifiée, delivery_id dédupliqué.
3. Token d'installation généré (JWT App + échange).
4. Fichiers Python modifiés récupérés en lecture seule.
5. Contenu envoyé à `POST /api/v1/review/repository` du Core Engine.
6. Résumé publié comme check run — aucune écriture sur le dépôt.

## Ancrage et validation de patch

Un patch n'existe jamais de façon autonome : il est toujours ancré à `(document_sha256, document_version, anchor_range)`. Toute divergence entre cet ancrage et l'état courant du document invalide le patch avant même la prévisualisation diff.
