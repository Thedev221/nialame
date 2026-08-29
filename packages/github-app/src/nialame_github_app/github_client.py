"""Client GitHub minimal pour les besoins du MVP.

Ne fait que :
- générer un JWT d'application et échanger un token d'installation ;
- lire les fichiers modifiés d'une pull request ;
- créer un check run avec un résumé.

Aucune écriture de fichier, aucun push, aucune création de branche.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import jwt

from nialame_github_app.config import settings

_GITHUB_API_BASE = "https://api.github.com"


class GitHubAuthError(RuntimeError):
    pass


def _build_app_jwt() -> str:
    if not settings.github_app_id:
        raise GitHubAuthError("GITHUB_APP_ID non configuré.")

    key_path = Path(settings.github_app_private_key_path)
    if not key_path.exists():
        raise GitHubAuthError(f"Clé privée introuvable: {key_path}")

    private_key = key_path.read_text(encoding="utf-8")
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 9 * 60,
        "iss": settings.github_app_id,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


@dataclass
class InstallationToken:
    token: str
    expires_at: str


async def get_installation_token(installation_id: int) -> InstallationToken:
    app_jwt = _build_app_jwt()
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            f"{_GITHUB_API_BASE}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
            },
        )
        response.raise_for_status()
        data = response.json()
    return InstallationToken(token=data["token"], expires_at=data["expires_at"])


async def list_pull_request_files(
    installation_token: str, repo_full_name: str, pr_number: int
) -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            f"{_GITHUB_API_BASE}/repos/{repo_full_name}/pulls/{pr_number}/files",
            headers={
                "Authorization": f"Bearer {installation_token}",
                "Accept": "application/vnd.github+json",
            },
            params={"per_page": 100},
        )
        response.raise_for_status()
        return response.json()


async def fetch_file_content(
    installation_token: str, repo_full_name: str, path: str, ref: str
) -> str | None:
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            f"{_GITHUB_API_BASE}/repos/{repo_full_name}/contents/{path}",
            headers={
                "Authorization": f"Bearer {installation_token}",
                "Accept": "application/vnd.github.raw+json",
            },
            params={"ref": ref},
        )
        if response.status_code != 200:
            return None
        return response.text


async def create_check_run(
    installation_token: str,
    repo_full_name: str,
    head_sha: str,
    conclusion: str,
    title: str,
    summary_markdown: str,
) -> dict:
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            f"{_GITHUB_API_BASE}/repos/{repo_full_name}/check-runs",
            headers={
                "Authorization": f"Bearer {installation_token}",
                "Accept": "application/vnd.github+json",
            },
            json={
                "name": "Nialame Security Review",
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {"title": title, "summary": summary_markdown},
            },
        )
        response.raise_for_status()
        return response.json()
