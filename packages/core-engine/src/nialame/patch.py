"""Ancrage et validation de patch.

Un patch n'est jamais appliqué à l'aveugle : il est ancré à un hash de
document, une version et une plage de lignes précise. Toute divergence
entre l'état ancré et l'état courant du document invalide le patch.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
from dataclasses import dataclass

from nialame.models import DocumentRef, Finding, Range, Severity, SuggestedPatch
from nialame.scanner import scan_python_source

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass
class PatchValidationOutcome:
    valid: bool
    reasons: list[str]
    new_findings_introduced: list[Finding]
    patched_source: str | None


def _apply_range_replacement(original: str, anchor: Range, replacement_lines: list[str]) -> str:
    lines = original.splitlines(keepends=True)
    start_idx = anchor.start_line - 1
    end_idx = anchor.end_line  # end_line est inclusif, slice exclusive => pas de -1
    if start_idx < 0 or end_idx > len(lines) or start_idx > end_idx:
        raise ValueError("Plage d'ancrage hors limites du document.")
    new_lines = lines[:start_idx] + [line + "\n" for line in replacement_lines] + lines[end_idx:]
    return "".join(new_lines)


def _extract_replacement_lines_from_diff(unified_diff: str) -> list[str]:
    """Extrait les lignes ajoutées (`+`) d'un unified diff simple à un seul hunk."""
    replacement: list[str] = []
    for line in unified_diff.splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            replacement.append(line[1:])
    return replacement


def validate_and_apply_patch(
    document: DocumentRef, patch: SuggestedPatch
) -> PatchValidationOutcome:
    reasons: list[str] = []

    if document.sha256 != patch.document_sha256:
        reasons.append(
            "Le hash SHA-256 du document ne correspond pas au hash ancré dans le patch : "
            "le document a changé depuis l'analyse."
        )
    if document.version != patch.document_version:
        reasons.append(
            "La version du document ne correspond pas à la version ancrée dans le patch."
        )

    if reasons:
        return PatchValidationOutcome(
            valid=False, reasons=reasons, new_findings_introduced=[], patched_source=None
        )

    if document.content is None:
        reasons.append("Contenu du document non fourni : impossible de valider le patch.")
        return PatchValidationOutcome(
            valid=False, reasons=reasons, new_findings_introduced=[], patched_source=None
        )

    try:
        replacement_lines = _extract_replacement_lines_from_diff(patch.unified_diff)
        patched_source = _apply_range_replacement(
            document.content, patch.anchor_range, replacement_lines
        )
    except ValueError as exc:
        reasons.append(str(exc))
        return PatchValidationOutcome(
            valid=False, reasons=reasons, new_findings_introduced=[], patched_source=None
        )

    try:
        ast.parse(patched_source)
    except SyntaxError as exc:
        reasons.append(f"Le patch produit un code syntaxiquement invalide : {exc}")
        return PatchValidationOutcome(
            valid=False, reasons=reasons, new_findings_introduced=[], patched_source=None
        )

    original_findings = scan_python_source(document.content)
    new_findings = scan_python_source(patched_source)

    original_max = max((_SEVERITY_ORDER[f.severity] for f in original_findings), default=-1)
    regressions = [
        f for f in new_findings if _SEVERITY_ORDER[f.severity] >= max(original_max, 0)
    ]
    # On ne considère une régression que si un finding équivalent n'existait pas déjà
    original_rule_ids = {f.rule_id for f in original_findings}
    regressions = [f for f in regressions if f.rule_id not in original_rule_ids]

    if regressions:
        reasons.append(
            "Le patch introduit de nouvelles alertes de sévérité égale ou supérieure."
        )
        return PatchValidationOutcome(
            valid=False,
            reasons=reasons,
            new_findings_introduced=regressions,
            patched_source=patched_source,
        )

    return PatchValidationOutcome(
        valid=True, reasons=[], new_findings_introduced=[], patched_source=patched_source
    )


def build_unified_diff(
    original: str, patched: str, file_label: str = "document"
) -> str:
    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{file_label}",
        tofile=f"b/{file_label}",
    )
    return "".join(diff)
