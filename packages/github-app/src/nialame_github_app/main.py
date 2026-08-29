"""Point d'entrée FastAPI de la GitHub App Nialame AI.

Flux pull_request :
1. Vérification signature HMAC.
2. Déduplication par delivery_id.
3. Parsing du payload (Pydantic, extra="ignore").
4. Génération d'un token d'installation.
5. Lecture des fichiers Python modifiés dans la PR.
6. Appel du Core Engine (analyse déterministe uniquement).
7. Publication d'un check run résumant les findings.

Aucun commentaire inline par défaut, aucune écriture, aucun push,
aucune création de branche.
"""
from __future__ import annotations

import logging

import httpx
from fastapi import FastAPI, Header, HTTPException, Request

from nialame_github_app.config import settings
from nialame_github_app.dedup import DeliveryDeduplicator
from nialame_github_app.github_client import (
    GitHubAuthError,
    create_check_run,
    fetch_file_content,
    get_installation_token,
    list_pull_request_files,
)
from nialame_github_app.models import PullRequestEvent
from nialame_github_app.summary import build_summary_markdown
from nialame_github_app.webhook_signature import InvalidWebhookSignatureError, verify_signature

logging.basicConfig(level="INFO")
logger = logging.getLogger("nialame.github_app")

app = FastAPI(
    title="Nialame AI — GitHub App",
    version="0.1.0",
    description="Analyse de pull requests et publication de résumés de sécurité.",
)

_deduplicator = DeliveryDeduplicator(ttl_seconds=settings.webhook_dedup_ttl_seconds)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/install")
async def install() -> dict[str, str]:
    return {
        "message": "Installez la GitHub App Nialame depuis la marketplace ou l'URL fournie par votre organisation.",
    }


@app.get("/callback")
async def callback(code: str | None = None) -> dict[str, str]:
    if not code:
        raise HTTPException(status_code=400, detail="Paramètre 'code' manquant.")
    return {"status": "installation reçue", "note": "Échange du code géré côté configuration GitHub App."}


@app.post("/webhooks/github")
async def handle_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
) -> dict[str, str]:
    raw_body = await request.body()

    try:
        verify_signature(raw_body, x_hub_signature_256, settings.github_webhook_secret)
    except InvalidWebhookSignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    if not x_github_delivery:
        raise HTTPException(status_code=400, detail="En-tête X-GitHub-Delivery manquant.")

    if _deduplicator.is_duplicate(x_github_delivery):
        logger.info("Webhook dupliqué ignoré (delivery_id=%s)", x_github_delivery)
        return {"status": "duplicate_ignored"}

    logger.info("Webhook reçu: event=%s delivery_id=%s", x_github_event, x_github_delivery)

    if x_github_event == "pull_request":
        await _handle_pull_request_event(await request.json())
    elif x_github_event in {"installation", "installation_repositories", "push"}:
        logger.info("Événement %s reçu, aucune action requise dans le MVP.", x_github_event)
    else:
        logger.info("Événement %s ignoré (non supporté).", x_github_event)

    return {"status": "accepted"}


async def _handle_pull_request_event(payload: dict) -> None:
    event = PullRequestEvent.model_validate(payload)

    if event.action not in {"opened", "synchronize", "reopened"}:
        return

    installation = event.installation
    if not installation:
        logger.warning("Événement pull_request sans installation associée, ignoré.")
        return

    try:
        token = await get_installation_token(installation["id"])
    except GitHubAuthError as exc:
        logger.error("Échec d'authentification GitHub App: %s", exc)
        return

    repo_full_name = event.repository.full_name
    head_sha = event.pull_request.get("head", {}).get("sha")
    if not head_sha:
        return

    files = await list_pull_request_files(token.token, repo_full_name, event.number)
    python_files = [f for f in files if f["filename"].endswith(".py") and f["status"] != "removed"]

    file_contents: dict[str, str] = {}
    for f in python_files:
        content = await fetch_file_content(token.token, repo_full_name, f["filename"], head_sha)
        if content is not None:
            file_contents[f["filename"]] = content

    if not file_contents:
        results: list[dict] = []
    else:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{settings.core_engine_url}/api/v1/review/repository",
                json={"files": file_contents, "allow_llm": False},
            )
            response.raise_for_status()
            review = response.json()
        results = review["results"]

    conclusion, title, summary_markdown = build_summary_markdown(results)

    await create_check_run(
        token.token, repo_full_name, head_sha, conclusion, title, summary_markdown
    )

    if settings.enable_inline_comments:
        logger.info(
            "Commentaires inline activés mais non implémentés dans ce MVP (fonctionnalité future)."
        )
