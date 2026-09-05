# Nialame AI V1.0 — Définition exacte et feuille de route

**Statut :** proposition à valider — ajustée à partir de la première ébauche, en respectant trois contraintes fixées : au moins 3 langages, au moins 100 règles de détection, et le retrait de toute automatisation qui contredirait le principe fondateur du projet (aucune action sans validation humaine explicite).

---

## Nialame AI V1.0 — Description exacte

Nialame AI V1.0 est un scanner de sécurité et un assistant de correction de code **local-first, multi-langage**. Son objectif : intercepter, expliquer et corriger les vulnérabilités applicatives directement dans l'environnement du développeur, sans aucune fuite de données vers le cloud, et **sans jamais agir sans validation humaine explicite**.

### Architecture : un cerveau central, des interfaces dédiées

Toutes les fonctionnalités reposent sur un moteur unique, le **Core Engine** (`packages/core-engine`). Les règles de sécurité, les parsers d'Arbre de Syntaxe Abstraite (AST) pour chaque langage, et l'IA locale y sont centralisés. Améliorer une règle dans le Core Engine la rend immédiatement active sur tous les points d'accès (extension, Action, App).

---

### 1. Core Engine — Moteur de détection AST & IA

- **Analyse déterministe : au moins 100 règles de sécurité** couvrant les catégories majeures de l'OWASP Top 10 (injections SQL/commandes, secrets exposés, désérialisation non sûre, cryptographie faible, TLS mal configuré, etc.).
- **Support multi-langage : Python, JavaScript/TypeScript, Go.**
- **Souveraineté** : exécution 100% locale (analyse statique Tier 1 + LLM local optionnel via Ollama, Tier 2). Le Tier 1 reste opérationnel même sans LLM.

### 2. Extension VS Code — l'interface développeur

- **Analyse au fil de l'eau** : scan à la sauvegarde, sur sélection, sur workspace entier.
- **Visualisation** : findings remontés dans un panneau dédié et la barre de statut, sans diagnostic intrusif dans l'éditeur.
- **Correction assistée, jamais automatique** : prévisualisation diff systématique avant toute application, confirmation explicite requise, ancrage hash/version pour éviter tout patch obsolète.

### 3. GitHub Action — le gardien CI/CD

- **Quality Gate** : scan automatisé à chaque pull request.
- **Rapport SARIF standard**, intégré nativement à l'onglet Security de GitHub.
- **Blocage de build configurable** : échec du job CI/CD selon la sévérité trouvée (`fail-on`), empêchant la fusion de code vulnérable si l'équipe le configure ainsi.

### 4. GitHub App — l'assistant interactif de pull request

- **Résumé de sécurité automatique** publié comme check run sur chaque pull request.
- **Commandes ChatOps** (`@nialame scan`, `@nialame explain <finding>`) pour interagir directement en commentaire de PR.
- **Proposition de correctif en commentaire, avec diff visible** — **jamais de commit ou de push automatique**. Un humain doit explicitement copier, adapter et committer lui-même le correctif proposé. Ce point remplace et corrige l'ancienne formulation ("génération et soumission automatique de commits") qui contredisait le principe fondateur du projet.

---

## Ce qui est volontairement HORS PÉRIMÈTRE de la V1.0

- **Scanner de dépendances / CVE (Supply Chain Security)** — un produit à part entière (bases de données CVE externes, parsing de multiples formats de dépendances par écosystème). Candidat naturel pour une V1.1 ou V2, une fois la base multi-langage solide.
- **Support de langages au-delà de Python/JS-TS/Go** (PHP, Java, C/C++, Rust...).
- **Toute automatisation qui committe, push, ou merge sans intervention humaine.**

---

## Feuille de route — 4 trimestres

### T1 — Python solide + fondations JavaScript/TypeScript
- Python : 9 → 40 règles.
- Démarrage du parser AST JavaScript/TypeScript (via une bibliothèque existante, ex. Babel parser ou esprima — pas de réinvention).
- Objectif de fin de trimestre : 15-20 règles JS/TS fonctionnelles.

### T2 — JavaScript/TypeScript complet + démarrage Go
- JS/TS : finir à 35 règles.
- Démarrage du support Go (`go/ast`, natif dans la stdlib Go).
- GitHub App testée en conditions réelles pour la première fois (webhooks, check runs, commandes ChatOps).
- "Mark as false positive" / "Ignore rule in file" rendus réellement persistants (actuellement des coquilles vides).

### T3 — Go complet + qualité et fiabilité
- Go : finir à 25 règles → **100 règles au total atteintes**.
- Tests automatisés de l'extension VS Code (actuellement absents).
- Validation réelle de la redaction de secrets en conditions réelles (jamais vérifiée manuellement à ce jour).
- Amélioration du Tier 2 : meilleur prompt, recommandation de modèle plus gros pour qui dispose de la puissance de calcul nécessaire.

### T4 — Stabilisation et sortie
- Correction des bugs remontés par la communauté durant les 3 premiers trimestres.
- Documentation complète et à jour pour les 3 langages.
- Revue de sécurité interne sur les zones sensibles (validation de patch, redaction, signature HMAC des webhooks).
- Publication du tag `v1.0.0`.

---

## Points ouverts à trancher avant validation finale

1. Répartition exacte des 100 règles entre les 3 langages (proposé : 40/35/25) — à ajuster selon la réalité du terrain une fois T1 entamé.
2. Ordre des langages (Python → JS/TS → Go proposé) — à confirmer.
3. Le périmètre exact des commandes ChatOps de la GitHub App pour le T2.
