# Nialame AI — Plan d'exécution vers la V1.0

Ce document répond à une seule question : **"je veux contribuer, par quoi je commence, et qu'est-ce qui vient après ?"** — sans jamais avoir besoin de demander la suite.

Chaque tâche ci-dessous a : un objectif clair, l'endroit exact où travailler dans le code, et une **définition de "terminé"** vérifiable (des tests qui passent, pas une impression subjective). Prends une tâche non cochée, dans l'ordre du trimestre en cours de préférence (certaines tâches dépendent d'autres, indiqué quand c'est le cas), ouvre une pull request en la référençant.

**Objectif final, dans 12 mois : Nialame AI V1.0** — 3 langages supportés (Python, JavaScript/TypeScript, Go), au moins 100 règles de détection, extension VS Code et GitHub App fiables et testées, aucune automatisation qui contredit la validation humaine.

---

## TRIMESTRE 1 — Python solide + fondations JavaScript/TypeScript

### T1.1 — Étendre les règles Python (9 → 40)
- **Où** : `packages/core-engine/src/nialame/scanner.py`, dictionnaire `_DANGEROUS_CALLS`.
- **Quoi** : ajouter des règles couvrant les catégories OWASP non encore traitées (ex. `tempfile.mktemp` non sûr, `subprocess.call` avec `shell=True`, `xml.etree` vulnérable au XXE, `random` utilisé pour un token de sécurité au lieu de `secrets`, assertions utilisées pour valider une entrée utilisateur).
- **Terminé quand** : chaque règle a un test dans `test_scanner.py` prouvant la détection ET l'absence de faux positif ; `pytest -v` passe intégralement ; 40 règles au total pour Python.
- **Dépendance** : aucune, peut démarrer immédiatement, plusieurs contributeurs peuvent s'y mettre en parallèle sur des règles différentes.

### T1.2 — Démarrer le parser AST JavaScript/TypeScript
- **Où** : nouveau module `packages/core-engine/src/nialame/scanner_js.py` (ou équivalent), utilisant une bibliothèque de parsing existante (ex. lier à `esprima`/`@babel/parser` via un sous-processus Node, ou une bibliothèque Python équivalente si elle existe).
- **Quoi** : poser la structure permettant de parser du JS/TS en une représentation exploitable, sur le modèle de ce que fait déjà `scanner.py` pour Python.
- **Terminé quand** : un fichier `.js` de test simple est parsé sans erreur et retourne une structure équivalente à ce que `ast.parse` retourne pour Python.
- **Dépendance** : aucune, indépendant de T1.1.

### T1.3 — Premières règles JavaScript/TypeScript (0 → 15-20)
- **Où** : le nouveau module créé en T1.2.
- **Quoi** : `eval()`, `child_process.exec()` avec entrée non filtrée, `innerHTML` avec donnée utilisateur (XSS), désérialisation JSON non sûre.
- **Terminé quand** : chaque règle testée comme en T1.1 ; 15-20 règles JS/TS fonctionnelles.
- **Dépendance** : nécessite T1.2 terminé.

**Fin de T1 validée quand** : Python à 40 règles, JS/TS à 15-20 règles, tous les tests passent, `main.py` route correctement selon le langage déclaré dans la requête.

---

## TRIMESTRE 2 — JavaScript/TypeScript complet + démarrage Go

### T2.1 — Compléter les règles JS/TS (15-20 → 35)
- **Où** : même module que T1.3.
- **Terminé quand** : 35 règles JS/TS au total, tests correspondants.
- **Dépendance** : suite de T1.3.

### T2.2 — Démarrer le support Go
- **Où** : nouveau module `packages/core-engine/src/nialame/scanner_go.py`, s'appuyant sur `go/ast` (nécessite d'invoquer un petit programme Go en sous-processus, ou une bibliothèque Python de parsing Go si suffisante).
- **Terminé quand** : un fichier `.go` simple est parsé sans erreur.
- **Dépendance** : aucune, indépendant de T2.1.

### T2.3 — GitHub App testée en conditions réelles
- **Où** : `packages/github-app/`.
- **Quoi** : configurer une vraie GitHub App de test, exposer le serveur local via un tunnel (ex. `ngrok`), déclencher une vraie pull request, vérifier que le check run apparaît correctement.
- **Terminé quand** : capture d'écran ou log prouvant qu'un webhook réel a été reçu, validé (HMAC), et a produit un check run visible sur une vraie PR.
- **Dépendance** : aucune, indépendant du reste du trimestre.

### T2.4 — Persistance réelle de "Mark as false positive" / "Ignore rule in file"
- **Où** : `packages/vscode-extension/src/providers/nialameViewProvider.ts` (actuellement juste une notification), + nouveau fichier de config local (ex. `.nialame-ignore.json` à la racine du workspace).
- **Terminé quand** : marquer un finding comme faux positif l'exclut réellement des scans suivants sur ce projet, avec un test qui le prouve.
- **Dépendance** : aucune.

**Fin de T2 validée quand** : JS/TS à 35 règles, Go parse correctement, GitHub App prouvée fonctionnelle sur une vraie PR, faux positifs réellement persistants.

---

## TRIMESTRE 3 — Go complet + qualité et fiabilité

### T3.1 — Compléter les règles Go (0 → 25)
- **Où** : module créé en T2.2.
- **Quoi** : `exec.Command` avec entrée non filtrée, `crypto/md5`/`crypto/sha1`, `math/rand` utilisé pour un usage sécuritaire, désérialisation `encoding/gob` non sûre.
- **Terminé quand** : 25 règles Go, tests correspondants. **→ 100 règles au total atteintes tous langages confondus.**
- **Dépendance** : suite de T2.2.

### T3.2 — Tests automatisés de l'extension VS Code
- **Où** : `packages/vscode-extension/tests/` (actuellement vide).
- **Quoi** : tests unitaires pour `documentHasher.ts`, `requestManager.ts`, `patchApplier.ts`, `gitService.ts`, et validation des messages Webview.
- **Terminé quand** : `npm test` exécute une suite de tests qui passe, couvrant au minimum le hash de document, le refus de patch obsolète, et le parsing de diff Git.
- **Dépendance** : aucune.

### T3.3 — Validation réelle de la redaction de secrets
- **Où** : test manuel + éventuellement un test d'intégration dans `packages/core-engine/tests/`.
- **Quoi** : créer un fichier avec un vrai secret factice (ex. une fausse clé API), activer le LLM, vérifier dans les logs/requête réseau que le secret n'atteint jamais Ollama en clair.
- **Terminé quand** : preuve documentée (capture ou log) que la redaction fonctionne de bout en bout, pas juste en test unitaire isolé.
- **Dépendance** : aucune.

### T3.4 — Amélioration du Tier 2
- **Où** : `packages/core-engine/src/nialame/llm.py`.
- **Quoi** : affiner le prompt de génération de patch pour réduire les erreurs d'indentation observées avec les petits modèles ; documenter les modèles recommandés selon la puissance de calcul disponible.
- **Terminé quand** : un patch généré sur le projet de démo passe la validation syntaxique sans erreur d'indentation, de façon reproductible.
- **Dépendance** : aucune.

**Fin de T3 validée quand** : 100 règles atteintes, extension testée automatiquement, redaction prouvée fiable, Tier 2 plus robuste.

---

## TRIMESTRE 4 — Stabilisation et sortie

### T4.1 — Correction des bugs remontés par la communauté
- **Où** : issues GitHub ouvertes durant les 3 premiers trimestres.
- **Terminé quand** : aucune issue ouverte marquée "bug bloquant".

### T4.2 — Documentation complète à jour pour les 3 langages
- **Où** : `docs/`, `README.md`, `CONTRIBUTING.md`.
- **Terminé quand** : chaque langage supporté a sa documentation d'usage, à jour avec le nombre réel de règles.

### T4.3 — Revue de sécurité interne
- **Où** : `patch.py`, `redaction.py`, `llm.py`, `webhook_signature.py`, `gitService.ts` (les zones sensibles listées dans `CONTRIBUTING.md`).
- **Terminé quand** : chaque fichier sensible a été relu par au moins une personne différente de son auteur original, avec les corrections nécessaires appliquées.

### T4.4 — Publication du tag v1.0.0
- **Terminé quand** : tag Git `v1.0.0` publié, avec notes de version résumant le chemin parcouru depuis le MVP.

---

## Comment savoir qu'on a atteint la V1.0

- ✅ 3 langages supportés (Python, JavaScript/TypeScript, Go)
- ✅ 100 règles de détection minimum, réparties sur les 3 langages
- ✅ Extension VS Code avec tests automatisés
- ✅ GitHub App prouvée fonctionnelle en conditions réelles
- ✅ Redaction de secrets validée en conditions réelles, pas juste en test unitaire
- ✅ Aucune fonctionnalité qui committe, push ou merge sans validation humaine explicite
- ✅ Tag `v1.0.0` publié
