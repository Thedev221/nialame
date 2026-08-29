"""Modèles Pydantic pour les payloads webhook GitHub pertinents au MVP.

Volontairement partiels : seuls les champs utilisés par Nialame sont
modélisés. ``model_config = {"extra": "ignore"}`` pour tolérer les
champs additionnels envoyés par GitHub sans les valider.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Repository(BaseModel):
    model_config = ConfigDict(extra="ignore")
    full_name: str
    default_branch: str


class PullRequestRef(BaseModel):
    model_config = ConfigDict(extra="ignore")
    number: int
    head_sha: str | None = None
    base_ref: str | None = None


class PullRequestEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    action: str
    number: int
    pull_request: dict
    repository: Repository
    installation: dict | None = None


class InstallationEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    action: str
    installation: dict


class PushEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ref: str
    repository: Repository
    installation: dict | None = None
