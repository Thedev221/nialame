"""Configuration centralisée du Core Engine, chargée depuis l'environnement.

Aucun secret ne doit avoir de valeur par défaut sensible. Le LLM est
désactivé par défaut (principe non négociable du projet).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    load_dotenv(dotenv_path=_env_path, override=False)
except ImportError:
    pass


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str = os.environ.get("NIALAME_HOST", "127.0.0.1")
    port: int = int(os.environ.get("NIALAME_PORT", "8000"))

    llm_enabled: bool = _bool_env("NIALAME_LLM_ENABLED", False)
    llm_provider: str = os.environ.get("NIALAME_LLM_PROVIDER", "ollama")
    llm_base_url: str = os.environ.get("NIALAME_LLM_BASE_URL", "http://127.0.0.1:11434")
    llm_model: str = os.environ.get("NIALAME_LLM_MODEL", "qwen2.5-coder:7b")
    llm_timeout_seconds: float = float(os.environ.get("NIALAME_LLM_TIMEOUT_SECONDS", "15"))
    llm_max_concurrency: int = int(os.environ.get("NIALAME_LLM_MAX_CONCURRENCY", "2"))

    max_document_bytes: int = int(os.environ.get("NIALAME_MAX_DOCUMENT_BYTES", str(512 * 1024)))
    max_context_chars: int = int(os.environ.get("NIALAME_MAX_CONTEXT_CHARS", "8000"))

    log_level: str = os.environ.get("NIALAME_LOG_LEVEL", "INFO")


settings = Settings()
