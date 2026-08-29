"""Configuration de la GitHub App, chargée depuis l'environnement."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AppSettings:
    host: str = os.environ.get("NIALAME_APP_HOST", "127.0.0.1")
    port: int = int(os.environ.get("NIALAME_APP_PORT", "8080"))

    github_app_id: str = os.environ.get("GITHUB_APP_ID", "")
    github_app_private_key_path: str = os.environ.get(
        "GITHUB_APP_PRIVATE_KEY_PATH", "./private-key.pem"
    )
    github_webhook_secret: str = os.environ.get("GITHUB_WEBHOOK_SECRET", "")

    core_engine_url: str = os.environ.get("NIALAME_CORE_ENGINE_URL", "http://127.0.0.1:8000")

    enable_inline_comments: bool = _bool_env("NIALAME_ENABLE_INLINE_COMMENTS", False)
    webhook_dedup_ttl_seconds: int = int(
        os.environ.get("NIALAME_WEBHOOK_DEDUP_TTL_SECONDS", "600")
    )


settings = AppSettings()
