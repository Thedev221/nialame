"""Analyse Tier 1 déterministe basée sur le module ``ast`` de la stdlib.

Ce module ne dépend d'aucun LLM et doit rester rapide (SLA visé < 50ms
pour un fichier de taille raisonnable). Il détecte un ensemble de motifs
de sécurité applicative connus : injection SQL, désérialisation non
sûre, exécution de code dynamique, etc.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from nialame.models import Confidence, Finding, Range, Severity

# Fonctions/appels connus pour être dangereux, mappés à une règle.
_DANGEROUS_CALLS: dict[str, dict[str, str]] = {
    "pickle.loads": {
        "rule_id": "NIA-DESER-001",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "message": "Désérialisation non sûre via pickle.loads sur une donnée potentiellement non fiable.",
    },
    "pickle.load": {
        "rule_id": "NIA-DESER-001",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "message": (
            "Désérialisation non sûre via pickle.load : un fichier ou flux non fiable "
            "peut contenir des données déclenchant l’exécution de code."
        ),
    },
    "yaml.load": {
        "rule_id": "NIA-DESER-002",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "message": "yaml.load sans Loader sûr peut exécuter du code arbitraire.",
    },
    "os.system": {
        "rule_id": "NIA-CMD-001",
        "cwe": "CWE-78",
        "severity": Severity.CRITICAL,
        "message": "Exécution de commande shell via os.system — risque d'injection de commande.",
    },
    "subprocess.call": {
        "rule_id": "NIA-CMD-002",
        "cwe": "CWE-78",
        "severity": Severity.MEDIUM,
        "message": "Appel subprocess — vérifier shell=False et l'absence d'interpolation de chaîne.",
    },
    "eval": {
        "rule_id": "NIA-EVAL-001",
        "cwe": "CWE-95",
        "severity": Severity.CRITICAL,
        "message": "Utilisation de eval() sur une entrée potentiellement contrôlée par l'utilisateur.",
    },
    "exec": {
        "rule_id": "NIA-EVAL-002",
        "cwe": "CWE-95",
        "severity": Severity.CRITICAL,
        "message": "Utilisation de exec() sur une entrée potentiellement contrôlée par l'utilisateur.",
    },
        "django.utils.safestring.mark_safe": {
        "rule_id": "NIA-XSS-001",
        "cwe": "CWE-79",
        "severity": Severity.HIGH,
        "message": "mark_safe désactive l'échappement automatique — risque de XSS si la chaîne contient une entrée utilisateur.",
    },
    "hashlib.md5": {
        "rule_id": "NIA-CRYPTO-001",
        "cwe": "CWE-327",
        "severity": Severity.MEDIUM,
        "message": "Algorithme de hachage cryptographiquement faible (MD5) — ne pas l'utiliser pour des mots de passe ou signatures.",
    },
    "hashlib.sha1": {
        "rule_id": "NIA-CRYPTO-001",
        "cwe": "CWE-327",
        "severity": Severity.MEDIUM,
        "message": "Algorithme de hachage cryptographiquement affaibli (SHA-1) — préférer SHA-256 ou supérieur.",
    },
    "subprocess.Popen": {
        "rule_id": "NIA-CMD-003",
        "cwe": "CWE-78",
        "severity": Severity.MEDIUM,
        "message": "Appel subprocess.Popen — vérifier shell=False et l'absence d'interpolation de chaîne dans la commande.",
    },
    "ssl._create_unverified_context": {
        "rule_id": "NIA-TLS-001",
        "cwe": "CWE-295",
        "severity": Severity.HIGH,
        "message": "Désactive la vérification de certificat TLS — expose à des attaques de type man-in-the-middle.",
    },
}

_MARK_SAFE_NAMES = {"mark_safe"}


@dataclass
class _CallSite:
    qualified_name: str
    node: ast.Call
    enclosing_symbol: str | None


class _EnclosingSymbolTracker(ast.NodeVisitor):
    """Parcourt l'AST en gardant trace de la fonction/classe englobante."""

    def __init__(self) -> None:
        self.call_sites: list[_CallSite] = []
        self._stack: list[str] = []
        self._sql_string_findings: list[ast.BinOp | ast.JoinedStr] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        qualified = _qualified_call_name(node)
        if qualified is not None:
            self.call_sites.append(
                _CallSite(
                    qualified_name=qualified,
                    node=node,
                    enclosing_symbol=self._current_symbol(),
                )
            )
        self.generic_visit(node)


def _qualified_call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = [func.attr]
        cur: ast.expr = func.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _looks_like_sql(text: str) -> bool:
    upper = text.upper()
    return any(kw in upper for kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP "))


class _SqlConcatVisitor(ast.NodeVisitor):
    """Détecte les requêtes SQL construites par concaténation/f-string."""

    def __init__(self) -> None:
        self.hits: list[tuple[ast.expr, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_BinOp(self, node: ast.BinOp) -> None:  # noqa: N802
        if isinstance(node.op, ast.Add):
            left = node.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str) and _looks_like_sql(left.value):
                self.hits.append((node, self._current_symbol()))
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:  # noqa: N802
        literal_parts = "".join(
            v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
        if _looks_like_sql(literal_parts) and any(isinstance(v, ast.FormattedValue) for v in node.values):
            self.hits.append((node, self._current_symbol()))
        self.generic_visit(node)


def scan_python_source(source: str) -> list[Finding]:
    """Analyse une source Python et retourne la liste des findings Tier 1.

    Lève ``SyntaxError`` si la source n'est pas un Python valide — à
    charge de l'appelant de gérer cette erreur (elle est utilisée aussi
    comme étape de validation syntaxique de patch).
    """
    tree = ast.parse(source)

    findings: list[Finding] = []

    call_tracker = _EnclosingSymbolTracker()
    call_tracker.visit(tree)
    for site in call_tracker.call_sites:
        rule = _DANGEROUS_CALLS.get(site.qualified_name)
        if rule is None:
            continue
        findings.append(
            Finding(
                rule_id=rule["rule_id"],
                cwe=rule.get("cwe"),
                severity=rule["severity"],
                confidence=Confidence.HIGH,
                message=rule["message"],
                explanation=(
                    f"L'appel à `{site.qualified_name}` correspond à une règle de sécurité "
                    "connue. Vérifiez l'origine des données passées à cet appel."
                ),
                proof=_render_node(source, site.node),
                location=_node_range(site.node),
                enclosing_symbol=site.enclosing_symbol,
                tier="tier1_deterministic",
            )
        )

    sql_visitor = _SqlConcatVisitor()
    sql_visitor.visit(tree)
    for node, symbol in sql_visitor.hits:
        findings.append(
            Finding(
                rule_id="NIA-SQLI-001",
                cwe="CWE-89",
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                message="Requête SQL potentiellement construite par concaténation de chaîne non paramétrée.",
                explanation=(
                    "La chaîne ressemble à une requête SQL et contient une valeur "
                    "interpolée dynamiquement. Utilisez des requêtes paramétrées "
                    "(placeholders) au lieu de la concaténation ou du f-string."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    return findings


def _node_range(node: ast.AST) -> Range:
    end_lineno = getattr(node, "end_lineno", None) or node.lineno
    end_col = getattr(node, "end_col_offset", None) or (node.col_offset + 1)
    return Range(
        start_line=node.lineno,
        start_column=node.col_offset,
        end_line=end_lineno,
        end_column=end_col,
    )


def _render_node(source: str, node: ast.AST) -> str:
    lines = source.splitlines()
    start = node.lineno - 1
    end = getattr(node, "end_lineno", node.lineno)
    snippet = lines[start:end]
    return "\n".join(snippet)[:400]


def find_enclosing_symbol(source: str, line: int) -> str | None:
    """Retrouve le nom de la fonction/méthode/classe englobant une ligne donnée."""
    tree = ast.parse(source)
    best: str | None = None
    best_span = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= line <= end:
                span = end - node.lineno
                if best_span is None or span < best_span:
                    best = node.name
                    best_span = span
    return best
