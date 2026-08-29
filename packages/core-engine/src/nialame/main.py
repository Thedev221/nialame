"""Point d'entrée FastAPI du Core Engine Nialame AI.

Ce module orchestre le pipeline en 16 étapes décrit dans le README, en
appelant les modules spécialisés (scanner, redaction, patch, sarif, llm).
Aucune logique d'analyse AST n'est dupliquée ici.
"""
from __future__ import annotations

import logging

import httpx
from fastapi import FastAPI, HTTPException

from nialame.config import settings
from nialame.llm import LlmDisabledError, LlmInvalidResponseError, generate_patch_for_finding
from nialame.models import (
    ChatContext,
    ChatRequest,
    ChatResponse,
    FileReviewResult,
    GitDiffReviewRequest,
    PatchValidateRequest,
    PatchValidateResponse,
    PrivacyMetadata,
    Reference,
    RepositoryReviewRequest,
    ReviewResponse,
    SarifRequest,
    SarifResponse,
    ScanRequest,
    ScanResponse,
)
from nialame.patch import build_unified_diff, compute_sha256, validate_and_apply_patch
from nialame.redaction import redact_for_llm
from nialame.sarif import build_sarif_report
from nialame.scanner import scan_python_source

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("nialame.core_engine")

app = FastAPI(
    title="Nialame AI — Core Engine",
    version="0.1.0",
    description="Moteur d'analyse de sécurité applicative (Tier 1 AST + Tier 2 LLM optionnel).",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "llm_enabled": str(settings.llm_enabled)}


def _guard_document_size(content: str | None) -> None:
    if content is None:
        return
    size = len(content.encode("utf-8"))
    if size > settings.max_document_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Document trop volumineux ({size} octets > "
                f"{settings.max_document_bytes} octets autorisés)."
            ),
        )


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    _guard_document_size(request.document.content)

    if request.document.content is None:
        raise HTTPException(status_code=400, detail="document.content est requis pour /scan.")

    actual_hash = compute_sha256(request.document.content)
    warnings: list[str] = []
    if actual_hash != request.document.sha256:
        warnings.append(
            "Le hash fourni ne correspond pas au contenu envoyé ; le hash recalculé a été utilisé."
        )

    try:
        findings = scan_python_source(request.document.content)
    except SyntaxError as exc:
        raise HTTPException(status_code=422, detail=f"Code Python invalide : {exc}") from exc

    return ScanResponse(
        request_id=request.request_id,
        document_sha256=actual_hash,
        findings=findings,
        suggested_patches=[],
        warnings=warnings,
        llm_used=False,
    )


@app.post("/api/v1/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    context_scope = request.scope.value
    llm_used = False
    redaction_types: list[str] = []
    findings: list = []
    references: list[Reference] = []
    warnings: list[str] = []
    suggested_patches: list = []
    redacted_source: str | None = None

    source_for_analysis = request.document.content if request.document else None

    if source_for_analysis is not None:
        _guard_document_size(source_for_analysis)
        try:
            findings = scan_python_source(source_for_analysis)
        except SyntaxError as exc:
            warnings.append(f"Analyse Tier 1 impossible : code invalide ({exc}).")

        redaction = redact_for_llm(source_for_analysis)
        redaction_types = redaction.redaction_types
        redacted_source = redaction.redacted_source

    # Quand la portée est "selection", on restreint les findings à la
    # plage sélectionnée : sans ce filtre, une explication demandée sur
    # un fragment renverrait tous les findings du fichier entier.
    if request.scope.value == "selection" and request.selection is not None:
        findings = [
            f
            for f in findings
            if f.location.start_line >= request.selection.start_line
            and f.location.start_line <= request.selection.end_line
        ]
        if not findings:
            warnings.append(
                "Aucun finding Tier 1 dans la sélection — le code choisi ne correspond à aucune règle connue."
            )

    targeted = _extract_mentioned_rule_id(request.message, findings)
    llm_explanation: str | None = None

    # Fix : on tente une génération de patch par le LLM (Tier 2) si le
    # serveur l'autorise ET que la requête le demande explicitement.
    # Le code envoyé au LLM est TOUJOURS la version redactée, jamais le
    # contenu brut — même si la redaction n'a rien trouvé à retirer.
    if (
        request.mode.value == "fix"
        and targeted is not None
        and request.document is not None
        and redacted_source is not None
        and settings.llm_enabled
        and request.options.allow_llm
    ):
        try:
            patch, llm_explanation = await generate_patch_for_finding(
                request.document, targeted, redacted_source
            )
            suggested_patches.append(patch)
            llm_used = True
        except LlmDisabledError as exc:
            warnings.append(str(exc))
        except LlmInvalidResponseError as exc:
            warnings.append(f"Le LLM a renvoyé une réponse invalide : {exc}")
        except httpx.HTTPError as exc:
            warnings.append(f"Impossible de contacter le serveur LLM (Ollama) : {exc}")

    # Ask / Explain : jamais de patch automatique.
    if targeted is not None:
        answer = _build_targeted_answer(request, targeted, llm_explanation, bool(suggested_patches))
    else:
        answer = _build_deterministic_answer(request, findings)

    if request.document and request.selection:
        references.append(
            Reference(
                uri_hash=compute_sha256(request.document.uri),
                range=request.selection,
                label=f"{request.document.uri}:{request.selection.start_line}",
            )
        )

    privacy = PrivacyMetadata(
        llm_used=llm_used,
        provider=request.options.provider if llm_used else None,
        context_redacted=bool(redaction_types),
        redaction_types=redaction_types,
        context_scope=context_scope,
    )

    return ChatResponse(
        request_id=request.request_id,
        conversation_id=request.conversation_id,
        answer_markdown=answer,
        references=references,
        findings=findings,
        suggested_patches=suggested_patches,
        warnings=warnings,
        privacy=privacy,
    )


def _extract_mentioned_rule_id(message: str, findings: list) -> object | None:
    """Retrouve, parmi les findings, celui dont le rule_id est mentionné dans le message."""
    for f in findings:
        if f.rule_id in message:
            return f
    return None


def _build_deterministic_answer(request: ChatRequest, findings: list) -> str:
    # Security / Review : c'est justement leur rôle de lister tous les
    # findings sans qu'on ait à le demander explicitement.
    if request.mode.value in ("security", "review"):
        if not findings:
            return (
                "Aucun problème détecté par l'analyse déterministe (Tier 1) sur ce fichier."
            )
        lines = [f"**{len(findings)} finding(s) détecté(s) par l'analyse Tier 1 :**", ""]
        for f in findings:
            lines.append(
                f"- `{f.rule_id}` ({f.severity.value}) — {f.message} (ligne {f.location.start_line})"
            )
        lines.append("")
        lines.append("_Revue humaine requise avant toute correction._")
        return "\n".join(lines)

    # Ask / Explain / Debug / Fix sans finding précis mentionné : pas de
    # LLM conversationnel branché sur ces modes dans ce MVP, donc pas de
    # vraie réponse en langage libre. Pour éviter de bombarder l'utilisateur
    # de findings sur un simple "bonjour", on reste bref et on l'oriente.
    if not findings:
        return (
            f"Le mode `{request.mode.value}` de Nialame ne fait pas encore de conversation libre "
            "(seul le Tier 1 déterministe est actif ici) — aucun problème de sécurité détecté "
            "dans ce fichier de toute façon."
        )

    return (
        f"Le mode `{request.mode.value}` de Nialame ne fait pas encore de conversation libre "
        "(seul le Tier 1 déterministe est actif sur ce mode). "
        f"{len(findings)} finding(s) sont présents dans ce fichier — mentionne un identifiant "
        "précis (ex. `NIA-EVAL-001`) pour une explication ciblée, ou passe en mode **Security** "
        "pour voir la liste complète."
    )
def _build_targeted_answer(
    request: ChatRequest, finding, llm_explanation: str | None = None, patch_generated: bool = False
) -> str:
    """Réponse ciblée sur un finding précis, adaptée au mode demandé."""
    header = f"**`{finding.rule_id}`** — {finding.severity.value.upper()} (ligne {finding.location.start_line})"

    if request.mode.value == "fix":
        if patch_generated:
            return "\n".join(
                [
                    header,
                    "",
                    finding.explanation,
                    "",
                    "✅ **Un patch a été généré par le LLM (Tier 2)** — à prévisualiser et valider "
                    "manuellement avant application.",
                    "",
                    llm_explanation or "(le LLM n'a pas fourni d'explication supplémentaire)",
                ]
            )

        return "\n".join(
            [
                header,
                "",
                finding.explanation,
                "",
                "```python",
                finding.proof,
                "```",
                "",
                "⚠️ **Aucun patch automatique n'a pu être généré.** Vérifie que le LLM (Tier 2) "
                "est activé (`NIALAME_LLM_ENABLED=true`), qu'Ollama tourne, et que la requête "
                "autorise explicitement le LLM (`allow_llm=true`).",
                "",
                "Voir `docs/development-and-deployment.md` pour la configuration Ollama.",
            ]
        )

    # explain / debug / security / ask / review : explication ciblée, pas de patch.
    return "\n".join(
        [
            header,
            "",
            finding.explanation,
            "",
            "**Extrait concerné :**",
            "```python",
            finding.proof,
            "```",
            "",
            "_Revue humaine requise avant toute correction._",
        ]
    )


@app.post("/api/v1/review/git-diff", response_model=ReviewResponse)
async def review_git_diff(request: GitDiffReviewRequest) -> ReviewResponse:
    results: list[FileReviewResult] = []
    warnings: list[str] = []

    current_file: str | None = None
    added_lines_buffer: list[str] = []

    def flush() -> None:
        nonlocal current_file, added_lines_buffer
        if current_file and added_lines_buffer:
            snippet = "\n".join(added_lines_buffer)
            try:
                findings = scan_python_source(snippet)
                if findings:
                    results.append(FileReviewResult(file_path=current_file, findings=findings))
            except SyntaxError:
                warnings.append(
                    f"Fragment de diff non auto-suffisant pour l'analyse AST : {current_file}"
                )
        added_lines_buffer = []

    for line in request.unified_diff.splitlines():
        if line.startswith("+++ b/"):
            flush()
            current_file = line[len("+++ b/"):]
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines_buffer.append(line[1:])
    flush()

    return ReviewResponse(request_id=request.request_id, results=results, warnings=warnings)


@app.post("/api/v1/review/repository", response_model=ReviewResponse)
async def review_repository(request: RepositoryReviewRequest) -> ReviewResponse:
    results: list[FileReviewResult] = []
    warnings: list[str] = []

    for path, content in request.files.items():
        if not path.endswith(".py"):
            continue
        _guard_document_size(content)
        try:
            findings = scan_python_source(content)
        except SyntaxError as exc:
            warnings.append(f"{path}: code invalide ({exc})")
            continue
        if findings:
            results.append(FileReviewResult(file_path=path, findings=findings))

    return ReviewResponse(request_id=request.request_id, results=results, warnings=warnings)


@app.post("/api/v1/patch/validate", response_model=PatchValidateResponse)
async def patch_validate(request: PatchValidateRequest) -> PatchValidateResponse:
    outcome = validate_and_apply_patch(request.document, request.patch)
    return PatchValidateResponse(
        request_id=request.request_id,
        valid=outcome.valid,
        reasons=outcome.reasons,
        new_findings_introduced=outcome.new_findings_introduced,
    )


@app.post("/api/v1/sarif", response_model=SarifResponse)
async def sarif(request: SarifRequest) -> SarifResponse:
    report = build_sarif_report(request.results, request.tool_name, request.tool_version)
    return SarifResponse(request_id=request.request_id, sarif=report)
