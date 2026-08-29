"""Redaction du code avant tout envoi à un LLM (Tier 2).

Deux passes :
1. Redaction regex sur les motifs de secrets connus (clés API, tokens,
   chaînes de connexion, mots de passe en dur).
2. Redaction AST-aware : remplace la valeur des littéraux assignés à des
   noms de variables évoquant un secret, indépendamment de la syntaxe
   exacte utilisée.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

_SECRET_VALUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}")),
    ("connection_string", re.compile(r"(?i)(postgres|mysql|mongodb)(\+\w+)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+")),
]

_SECRET_NAME_HINTS = re.compile(
    r"(?i)^(?:.*_)?(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)s?$"
)


@dataclass
class RedactionResult:
    redacted_source: str
    redaction_types: list[str]


def redact_secrets_regex(source: str) -> tuple[str, list[str]]:
    redacted = source
    applied: list[str] = []
    for label, pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(redacted):
            applied.append(label)
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted, applied


class _SecretAssignRedactor(ast.NodeTransformer):
    """Remplace la valeur littérale des assignations dont le nom évoque un secret."""

    def __init__(self) -> None:
        self.redacted_count = 0

    def visit_Assign(self, node: ast.Assign) -> ast.AST:  # noqa: N802
        for target in node.targets:
            if isinstance(target, ast.Name) and _SECRET_NAME_HINTS.match(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    node.value = ast.Constant(value="[REDACTED]")
                    self.redacted_count += 1
        self.generic_visit(node)
        return node


def redact_secrets_ast(source: str) -> tuple[str, bool]:
    """Redaction AST-aware. Retourne (source_modifiée, ast_valide).

    Si le parsing échoue (source invalide), retourne la source d'origine
    inchangée et ``ast_valide=False`` — la redaction regex reste
    applicable dans ce cas.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, False

    transformer = _SecretAssignRedactor()
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)

    if transformer.redacted_count == 0:
        return source, True

    try:
        return ast.unparse(new_tree), True
    except Exception:
        # Si unparse échoue pour une raison quelconque, on ne prend pas
        # le risque de renvoyer un code corrompu : fallback sur regex only.
        return source, True


def redact_for_llm(source: str) -> RedactionResult:
    """Pipeline complet de redaction avant envoi au LLM."""
    ast_redacted, _ = redact_secrets_ast(source)
    fully_redacted, regex_types = redact_secrets_regex(ast_redacted)

    types = list(regex_types)
    if ast_redacted != source:
        types.append("secret_variable_assignment")

    return RedactionResult(redacted_source=fully_redacted, redaction_types=types)
