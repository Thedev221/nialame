# Threat Model

## Actifs à protéger

- Code source de l'utilisateur (ne doit pas fuir vers un tiers non consenti).
- Secrets présents dans le code (clés API, mots de passe, tokens).
- Intégrité du dépôt Git (aucune modification non voulue).
- Confiance dans les suggestions du LLM (ne doit pas induire une fausse sécurité).

## Acteurs de menace considérés

1. **Code malveillant ou instructions cachées dans le code analysé** (prompt injection via commentaires/docstrings).
2. **Webhook GitHub falsifié** (tentative de déclencher une analyse ou une action sans autorisation).
3. **Rejeu de webhook** (delivery_id capturé et renvoyé).
4. **Extension VS Code compromise ou Webview malveillante** (tentative d'exécuter une commande arbitraire via postMessage).
5. **Fuite de secrets vers le LLM** (variable nommée `password`/`api_key` envoyée en clair dans le contexte).
6. **Patch appliqué sur un état de document obsolète** (race condition entre analyse et édition).

## Contre-mesures

| Menace | Contre-mesure |
|---|---|
| Prompt injection | Délimiteurs BEGIN_UNTRUSTED_CODE/END_UNTRUSTED_CODE ; le code est toujours traité comme donnée, jamais comme instruction système. |
| Webhook falsifié | Vérification HMAC obligatoire (`X-Hub-Signature-256`), rejet 401 sinon. |
| Rejeu de webhook | Déduplication par `delivery_id` avec TTL en mémoire. |
| Webview malveillante | Allowlist stricte de commandes (`ALLOWED_WEBVIEW_COMMANDS`), CSP sans `unsafe-inline`, nonce par chargement. |
| Fuite de secrets | Redaction regex + AST-aware avant tout envoi LLM ; LLM désactivé par défaut. |
| Patch obsolète | Ancrage hash+version+plage, re-vérifié juste avant l'écriture (`WorkspaceEdit`). |

## Hors périmètre (MVP)

- Protection contre un LLM local (Ollama) lui-même compromis ou empoisonné — hors contrôle de Nialame.
- Détection de vulnérabilités zero-day non couvertes par les règles Tier 1 existantes.
- Analyse multi-langage (réservée à une itération future via Tree-sitter).

## Limites explicites

Nialame ne remplace ni un audit de sécurité manuel ni un test d'intrusion. Le Tier 1 est un ensemble de règles connues, pas une preuve d'absence de vulnérabilité.
