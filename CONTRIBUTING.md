# Contribuer à Nialame AI

Merci de t'intéresser à Nialame AI ! Ce document explique comment
contribuer efficacement, que ce soit pour corriger un bug, ajouter une
règle de détection, ou améliorer la documentation.

## Premier bon ticket : ajouter une règle de détection

Le scanner Tier 1 vit dans :
packages/core-engine/src/nialame/scanner.py

Regarde le dictionnaire `_DANGEROUS_CALLS` — chaque entrée associe un
appel de fonction dangereux à une règle avec un identifiant, une
sévérité, un CWE, et un message.

## Mise en place de l'environnement

git clone https://github.com/Thedev221/nialame.git
cd nialame/packages/core-engine
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v

## Tests obligatoires avant toute pull request

- Core Engine : pytest -v doit passer intégralement.
- Extension VS Code : npm run compile doit réussir sans erreur.
