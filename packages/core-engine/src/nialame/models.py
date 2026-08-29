"""Contrats Pydantic v2 pour tous les endpoints du Core Engine.

Ces modèles sont la source de vérité du format d'échange entre le
Core Engine et ses clients (extension VS Code, GitHub Action, GitHub App).
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Types communs
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Range(BaseModel):
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=0)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=0)

    @field_validator("end_line")
    @classmethod
    def end_line_after_start(cls, v: int, info: Any) -> int:
        start_line = info.data.get("start_line")
        if start_line is not None and v < start_line:
            raise ValueError("end_line doit être >= start_line")
        return v


class DocumentRef(BaseModel):
    uri: str
    version: int = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)
    content: str | None = None


class Finding(BaseModel):
    rule_id: str
    cwe: str | None = None
    severity: Severity
    confidence: Confidence
    message: str
    explanation: str
    proof: str
    location: Range
    enclosing_symbol: str | None = None
    tier: Literal["tier1_deterministic", "tier2_llm"]


class SuggestedPatch(BaseModel):
    finding_rule_id: str
    document_sha256: str
    document_version: int
    anchor_range: Range
    unified_diff: str
    human_review_required: bool = True
    assumptions: list[str] = Field(default_factory=list)
    validations_performed: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /api/v1/scan
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    language: Literal["python"] = "python"
    document: DocumentRef
    allow_llm: bool = False


class ScanResponse(BaseModel):
    request_id: UUID
    document_sha256: str
    findings: list[Finding]
    suggested_patches: list[SuggestedPatch]
    warnings: list[str] = Field(default_factory=list)
    llm_used: bool = False


# ---------------------------------------------------------------------------
# /api/v1/chat
# ---------------------------------------------------------------------------

class ChatMode(str, Enum):
    ASK = "ask"
    EXPLAIN = "explain"
    DEBUG = "debug"
    SECURITY = "security"
    FIX = "fix"
    REVIEW = "review"


class ChatScope(str, Enum):
    SELECTION = "selection"
    CURRENT_FILE = "current_file"
    OPEN_FILES = "open_files"
    WORKSPACE = "workspace"
    GIT_DIFF = "git_diff"
    PULL_REQUEST = "pull_request"


class RepositoryMetadata(BaseModel):
    name: str | None = None
    branch: str | None = None


class ChatContext(BaseModel):
    git_diff: str | None = None
    open_file_summaries: list[str] = Field(default_factory=list)
    repository_metadata: RepositoryMetadata | None = None


class ChatOptions(BaseModel):
    provider: Literal["ollama", "cloud_byok"] = "ollama"
    allow_llm: bool = False


class ChatRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    conversation_id: UUID = Field(default_factory=uuid4)
    mode: ChatMode
    scope: ChatScope
    message: str = Field(min_length=1, max_length=4000)
    language: Literal["python"] = "python"
    document: DocumentRef | None = None
    selection: Range | None = None
    context: ChatContext = Field(default_factory=ChatContext)
    options: ChatOptions = Field(default_factory=ChatOptions)


class Reference(BaseModel):
    uri_hash: str
    range: Range
    label: str


class PrivacyMetadata(BaseModel):
    llm_used: bool
    provider: str | None
    context_redacted: bool
    redaction_types: list[str] = Field(default_factory=list)
    context_scope: str


class ChatResponse(BaseModel):
    request_id: UUID
    conversation_id: UUID
    answer_markdown: str
    references: list[Reference] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    suggested_patches: list[SuggestedPatch] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    privacy: PrivacyMetadata


# ---------------------------------------------------------------------------
# /api/v1/review/git-diff, /api/v1/review/repository
# ---------------------------------------------------------------------------

class GitDiffReviewRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    unified_diff: str
    changed_files: list[str] = Field(default_factory=list)
    allow_llm: bool = False


class FileReviewResult(BaseModel):
    file_path: str
    findings: list[Finding]


class RepositoryReviewRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    files: dict[str, str] = Field(description="chemin relatif -> contenu du fichier")
    allow_llm: bool = False


class ReviewResponse(BaseModel):
    request_id: UUID
    results: list[FileReviewResult]
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /api/v1/patch/validate
# ---------------------------------------------------------------------------

class PatchValidateRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    document: DocumentRef
    patch: SuggestedPatch


class PatchValidateResponse(BaseModel):
    request_id: UUID
    valid: bool
    reasons: list[str] = Field(default_factory=list)
    new_findings_introduced: list[Finding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /api/v1/sarif
# ---------------------------------------------------------------------------

class SarifRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    results: list[FileReviewResult]
    tool_name: str = "nialame-ai"
    tool_version: str = "0.1.0"


class SarifResponse(BaseModel):
    request_id: UUID
    sarif: dict[str, Any]
