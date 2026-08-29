FROM python:3.12-slim

WORKDIR /action

# Le Core Engine est copié en tant que dépendance locale : la Action
# n'a pas de logique d'analyse propre, elle appelle le même moteur que
# l'IDE et la GitHub App.
#
# IMPORTANT : ce chemin suppose que l'image est construite avec un
# CONTEXTE DE BUILD À LA RACINE DU DÉPÔT (pas depuis ce dossier), car
# Docker interdit de copier un fichier situé en dehors du contexte de
# build. Exemple de commande correcte, depuis la racine du dépôt :
#   docker build -f packages/github-action/Dockerfile -t nialame-action .
COPY packages/core-engine /action/core-engine
RUN pip install --no-cache-dir -e /action/core-engine

COPY packages/github-action/entrypoint.sh /action/entrypoint.sh
RUN chmod +x /action/entrypoint.sh

ENTRYPOINT ["/action/entrypoint.sh"]
