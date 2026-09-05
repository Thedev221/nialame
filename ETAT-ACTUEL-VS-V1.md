# Nialame AI — État actuel (MVP) vs V1.0

Comparaison directe, composant par composant, pour identifier précisément l'écart à combler.

---

## 1. Core Engine

| | État actuel (MVP) | Cible V1.0 | Écart |
|---|---|---|---|
| Règles de détection | **9** | 100 minimum | **+91 règles** |
| Langages supportés | **1 (Python)** | 3 (Python, JS/TS, Go) | **+2 langages** |
| Tier 1 (déterministe) | ✅ Fonctionnel, testé (27/27 tests) | — | Solide |
| Tier 2 (LLM local) | ✅ Fonctionnel, testé en conditions réelles avec Ollama (modèle 1.5b) | Modèle recommandé plus gros pour meilleure fiabilité | Fonctionne mais qualité perfectible |
| Redaction de secrets | ✅ Code écrit, tests unitaires passent | Validée manuellement en conditions réelles | **Jamais vérifiée à la main** |

## 2. Extension VS Code

| | État actuel (MVP) | Cible V1.0 | Écart |
|---|---|---|---|
| 8 commandes principales | ✅ Toutes testées en conditions réelles | — | Solide |
| Prévisualisation diff + application patch | ✅ Fonctionnelle, testée | — | Solide |
| "Mark as false positive" / "Ignore rule" | ❌ Coquilles vides (notification seulement, rien de persistant) | Persistance réelle par projet | **À construire entièrement** |
| Tests automatisés | ❌ Dossiers `tests/` vides | Suite de tests complète | **À écrire entièrement** |

## 3. GitHub Action

| | État actuel (MVP) | Cible V1.0 | Écart |
|---|---|---|---|
| Scan sur pull request | ✅ Testé en conditions réelles | — | Solide |
| Rapport SARIF | ✅ Généré et validé | — | Solide |
| Blocage de build configurable | ✅ Fonctionnel (`fail-on`) | — | Solide |
| Annotations ligne par ligne sur PR | ❌ Non implémenté (seulement SARIF global) | Commentaires ciblés par ligne | À construire |

## 4. GitHub App

| | État actuel (MVP) | Cible V1.0 | Écart |
|---|---|---|---|
| Code écrit (webhooks, HMAC, check runs) | ✅ Écrit, compile | — | Base posée |
| Testée en conditions réelles | ❌ **Jamais testée** (nécessite ngrok ou équivalent) | Testée et fiable | **Aucune preuve de fonctionnement réel** |
| Commandes ChatOps (`@nialame scan`) | ❌ N'existe pas | Fonctionnalité complète | **À construire entièrement** |

## Hors périmètre actuel (ni MVP ni V1.0 pour l'instant)

- Scanner de dépendances / CVE (Supply Chain) — explicitement reporté après la V1.0.

---

## Ce que ça donne concrètement : priorités immédiates

L'écart le plus important et le plus structurant est **le Core Engine** — tout le reste (extension, Action, App) dépend de lui. Logiquement, les toutes premières actions concrètes à mener sont :

1. **Écrire des règles Python supplémentaires** (9 → 40) — travail direct dans `scanner.py`, aucune dépendance externe.
2. **Démarrer le parser AST JavaScript/TypeScript** — la plus grosse marche technique à franchir, puisque ça demande d'intégrer une bibliothèque de parsing externe (Babel/esprima) et de dupliquer la logique de détection dans un nouveau module.
3. **En parallèle, plus simple et indépendant** : valider réellement la redaction de secrets (juste un test manuel avec un vrai secret dans un fichier), et rendre "Mark as false positive"/"Ignore rule" persistants (petit fichier de config JSON par projet, pas besoin d'infrastructure lourde).

Ces trois chantiers peuvent avancer en parallèle sans se bloquer mutuellement, puisqu'ils touchent des fichiers différents du projet.
