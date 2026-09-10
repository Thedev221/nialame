
"""Analyse Tier 1 déterministe basée sur le module ``ast`` de la stdlib.

Ce module ne dépend d'aucun LLM et doit rester rapide (SLA visé < 50ms
pour un fichier de taille raisonnable). Il détecte un ensemble de motifs
de sécurité applicative connus : injection SQL, désérialisation non
sûre, exécution de code dynamique, etc.
"""
from __future__ import annotations

import ast
import re
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
    "os.popen": {
        "rule_id": "NIA-CMD-004",
        "cwe": "CWE-78",
        "severity": Severity.CRITICAL,
        "message": "Exécution de commande shell via os.popen — risque d'injection de commande.",
    },
    "pickle.load": {
        "rule_id": "NIA-DESER-001",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "message": "Désérialisation non sûre via pickle.load sur une donnée potentiellement non fiable.",
    },
    "xml.etree.ElementTree.fromstring": {
        "rule_id": "NIA-XXE-001",
        "cwe": "CWE-611",
        "severity": Severity.HIGH,
        "message": "Parsing XML potentiellement vulnérable aux attaques XXE (XML External Entity) sur une entrée non fiable.",
    },
        "tempfile.mktemp": {
        "rule_id": "NIA-TMPFILE-001",
        "cwe": "CWE-377",
        "severity": Severity.MEDIUM,
        "message": "tempfile.mktemp crée un nom de fichier sans le créer atomiquement — condition de course exploitable. Utiliser tempfile.mkstemp ou NamedTemporaryFile.",
    },
    "yaml.unsafe_load": {
        "rule_id": "NIA-DESER-003",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "message": "yaml.unsafe_load exécute explicitement du code arbitraire caché dans un fichier YAML.",
    },
    "marshal.loads": {
        "rule_id": "NIA-DESER-004",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "message": "marshal.loads désérialise des données non fiables — risque d'exécution de code arbitraire.",
    },
    "jsonpickle.decode": {
        "rule_id": "NIA-DESER-005",
        "cwe": "CWE-502",
        "severity": Severity.HIGH,
        "message": "jsonpickle.decode peut désérialiser des objets Python arbitraires depuis une donnée non fiable.",
    },
    "paramiko.AutoAddPolicy": {
        "rule_id": "NIA-SSH-001",
        "cwe": "CWE-295",
        "severity": Severity.HIGH,
        "message": "AutoAddPolicy accepte aveuglément n'importe quelle clé d'hôte SSH — expose à une attaque man-in-the-middle.",
    },
        "DES.new": {
        "rule_id": "NIA-CRYPTO-002",
        "cwe": "CWE-327",
        "severity": Severity.MEDIUM,
        "message": "DES est un algorithme de chiffrement cryptographiquement cassé — utiliser AES à la place.",
    },
    "ARC4.new": {
        "rule_id": "NIA-CRYPTO-002",
        "cwe": "CWE-327",
        "severity": Severity.MEDIUM,
        "message": "RC4 est un algorithme de chiffrement cryptographiquement cassé — utiliser AES à la place.",
    },
    "ssl.wrap_socket": {
        "rule_id": "NIA-TLS-002",
        "cwe": "CWE-295",
        "severity": Severity.MEDIUM,
        "message": "ssl.wrap_socket est déprécié et ne valide pas correctement les certificats — utiliser ssl.SSLContext.",
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
_SECRET_NAME_HINTS_SCANNER = re.compile(
    r"(?i)^(?:.*_)?(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)s?$"
)


class _SecuritySensitiveAssignVisitor(ast.NodeVisitor):
    """Détecte trois motifs distincts sur les assignations :
    secrets codés en dur, aléatoire faible pour un usage sécuritaire,
    et mode debug activé (Django DEBUG = True)."""

    def __init__(self) -> None:
        self.hits: list[tuple[str, ast.AST, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            if target.id == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                self.hits.append(("debug", node, self._current_symbol()))
                continue

            if not _SECRET_NAME_HINTS_SCANNER.match(target.id):
                continue

            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                self.hits.append(("secret", node, self._current_symbol()))
            elif isinstance(node.value, ast.Call):
                qualified = _qualified_call_name(node.value)
                if qualified in {"random.random", "random.randint", "random.choice", "random.uniform"}:
                    self.hits.append(("weak_random", node, self._current_symbol()))

        self.generic_visit(node)


class _TimingUnsafeComparisonVisitor(ast.NodeVisitor):
    """Détecte une comparaison == sur une variable au nom évocateur d'un secret."""

    def __init__(self) -> None:
        self.hits: list[tuple[ast.AST, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Compare(self, node: ast.Compare) -> None:  # noqa: N802
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            operands = [node.left, *node.comparators]
            for operand in operands:
                if isinstance(operand, ast.Name) and _SECRET_NAME_HINTS_SCANNER.match(operand.id):
                    self.hits.append((node, self._current_symbol()))
                    break
        self.generic_visit(node)


class _DebugRunKwargVisitor(ast.NodeVisitor):
    """Détecte app.run(debug=True) ou équivalent, typique de Flask."""

    def __init__(self) -> None:
        self.hits: list[tuple[ast.AST, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        for kw in node.keywords:
            if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self.hits.append((node, self._current_symbol()))
        self.generic_visit(node)


class _DynamicPathVisitor(ast.NodeVisitor):
    """Détecte open()/os.path.join() avec un chemin construit dynamiquement (concat/f-string)."""

    def __init__(self) -> None:
        self.hits: list[tuple[ast.AST, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        qualified = _qualified_call_name(node)
        is_target = qualified in {"open", "os.path.join"}
        if is_target:
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    self.hits.append((node, self._current_symbol()))
                    break
                if isinstance(arg, ast.JoinedStr) and any(
                    isinstance(v, ast.FormattedValue) for v in arg.values
                ):
                    self.hits.append((node, self._current_symbol()))
                    break
        self.generic_visit(node)
class _SsrfSstiVisitor(ast.NodeVisitor):
    """Détecte trois motifs de construction dynamique dangereuse :
    SSTI (Jinja2), SSRF (requests), et verify=False (requests)."""

    _SSTI_TARGETS = {"Jinja2.from_string", "jinja2.Template", "Template"}
    _SSRF_TARGETS = {"requests.get", "requests.post", "requests.put", "requests.delete"}

    def __init__(self) -> None:
        self.ssti_hits: list[tuple[ast.AST, str | None]] = []
        self.ssrf_hits: list[tuple[ast.AST, str | None]] = []
        self.verify_false_hits: list[tuple[ast.AST, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    @staticmethod
    def _is_dynamic(arg: ast.expr) -> bool:
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            return True
        if isinstance(arg, ast.JoinedStr) and any(
            isinstance(v, ast.FormattedValue) for v in arg.values
        ):
            return True
        return False

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        qualified = _qualified_call_name(node)

        if qualified in self._SSTI_TARGETS and node.args and self._is_dynamic(node.args[0]):
            self.ssti_hits.append((node, self._current_symbol()))

        if qualified in self._SSRF_TARGETS:
            if node.args and self._is_dynamic(node.args[0]):
                self.ssrf_hits.append((node, self._current_symbol()))
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.verify_false_hits.append((node, self._current_symbol()))

        self.generic_visit(node)


class _OpenRedirectVisitor(ast.NodeVisitor):
    """Détecte redirect() avec un argument non littéral (Open Redirect)."""

    def __init__(self) -> None:
        self.hits: list[tuple[ast.AST, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        qualified = _qualified_call_name(node)
        if qualified == "redirect" and node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                self.hits.append((node, self._current_symbol()))
        self.generic_visit(node)
class _AdvancedPatternVisitor(ast.NodeVisitor):
    """Détecte 6 motifs avancés supplémentaires, ancrés dans des CVE réels."""

    _SHELL_TRUE_TARGETS = {"subprocess.run", "subprocess.check_output", "subprocess.check_call"}

    def __init__(self) -> None:
        self.zip_slip_hits: list[tuple[ast.AST, str | None]] = []
        self.shell_true_hits: list[tuple[ast.AST, str | None]] = []
        self.jwt_hits: list[tuple[ast.AST, str | None]] = []
        self.xxe_lxml_hits: list[tuple[ast.AST, str | None]] = []
        self.cors_wildcard_hits: list[tuple[ast.AST, str | None]] = []
        self.ecb_mode_hits: list[tuple[ast.AST, str | None]] = []
        self._stack: list[str] = []

    def _current_symbol(self) -> str | None:
        return self._stack[-1] if self._stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        qualified = _qualified_call_name(node)

        if isinstance(node.func, ast.Attribute) and node.func.attr == "extractall":
            self.zip_slip_hits.append((node, self._current_symbol()))

        if qualified in self._SHELL_TRUE_TARGETS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.shell_true_hits.append((node, self._current_symbol()))

        if qualified == "jwt.decode":
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.jwt_hits.append((node, self._current_symbol()))
                if kw.arg == "algorithms" and isinstance(kw.value, ast.List):
                    for elt in kw.value.elts:
                        if (
                            isinstance(elt, ast.Constant)
                            and isinstance(elt.value, str)
                            and elt.value.lower() == "none"
                        ):
                            self.jwt_hits.append((node, self._current_symbol()))

        if qualified in {"etree.XMLParser", "lxml.etree.XMLParser"}:
            for kw in node.keywords:
                if kw.arg == "resolve_entities" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.xxe_lxml_hits.append((node, self._current_symbol()))

        if qualified == "CORS":
            for kw in node.keywords:
                if kw.arg == "origins" and isinstance(kw.value, ast.Constant) and kw.value.value == "*":
                    self.cors_wildcard_hits.append((node, self._current_symbol()))

        if qualified in {"AES.new", "Crypto.Cipher.AES.new"}:
            for arg in node.args:
                if isinstance(arg, ast.Attribute) and arg.attr == "MODE_ECB":
                    self.ecb_mode_hits.append((node, self._current_symbol()))

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

    security_assign_visitor = _SecuritySensitiveAssignVisitor()
    security_assign_visitor.visit(tree)
    for kind, node, symbol in security_assign_visitor.hits:
        if kind == "secret":
            findings.append(
                Finding(
                    rule_id="NIA-SECRET-001",
                    cwe="CWE-798",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    message="Secret potentiellement codé en dur dans le code source.",
                    explanation=(
                        "Une variable au nom évocateur d'un secret (password, token, "
                        "api_key...) est assignée à une chaîne littérale. Utilisez une "
                        "variable d'environnement ou un gestionnaire de secrets."
                    ),
                    proof=_render_node(source, node),
                    location=_node_range(node),
                    enclosing_symbol=symbol,
                    tier="tier1_deterministic",
                )
            )
        elif kind == "weak_random":
            findings.append(
                Finding(
                    rule_id="NIA-RANDOM-001",
                    cwe="CWE-330",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    message="Générateur aléatoire non cryptographique utilisé pour une valeur sensible.",
                    explanation=(
                        "random.random()/randint()/choice() n'est pas prévu pour un "
                        "usage sécuritaire — utilisez le module secrets à la place."
                    ),
                    proof=_render_node(source, node),
                    location=_node_range(node),
                    enclosing_symbol=symbol,
                    tier="tier1_deterministic",
                )
            )
        elif kind == "debug":
            findings.append(
                Finding(
                    rule_id="NIA-DEBUG-001",
                    cwe="CWE-215",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    message="Mode debug activé — ne jamais déployer en production ainsi.",
                    explanation=(
                        "DEBUG = True expose des informations sensibles (stack traces, "
                        "variables internes) si ce code atteint un environnement de production."
                    ),
                    proof=_render_node(source, node),
                    location=_node_range(node),
                    enclosing_symbol=symbol,
                    tier="tier1_deterministic",
                )
            )

    timing_visitor = _TimingUnsafeComparisonVisitor()
    timing_visitor.visit(tree)
    for node, symbol in timing_visitor.hits:
        findings.append(
            Finding(
                rule_id="NIA-TIMING-001",
                cwe="CWE-208",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                message="Comparaison directe (==) d'une valeur sensible — vulnérable à une attaque temporelle.",
                explanation=(
                    "Comparer un secret avec == peut fuiter sa valeur via le temps de "
                    "réponse. Utilisez hmac.compare_digest() à la place."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    debug_run_visitor = _DebugRunKwargVisitor()
    debug_run_visitor.visit(tree)
    for node, symbol in debug_run_visitor.hits:
        findings.append(
            Finding(
                rule_id="NIA-DEBUG-001",
                cwe="CWE-215",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                message="Mode debug activé — ne jamais déployer en production ainsi.",
                explanation=(
                    "Un serveur lancé avec debug=True (ex. Flask) expose un débogueur "
                    "interactif et des informations sensibles si atteint en production."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    path_visitor = _DynamicPathVisitor()
    path_visitor.visit(tree)
    for node, symbol in path_visitor.hits:
        findings.append(
            Finding(
                rule_id="NIA-PATH-001",
                cwe="CWE-22",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                message="Chemin de fichier potentiellement construit dynamiquement sans validation (Path Traversal).",
                explanation=(
                    "open()/os.path.join() reçoit un chemin assemblé par concaténation "
                    "ou f-string. Si une partie vient d'une entrée utilisateur, un "
                    "attaquant pourrait accéder à des fichiers hors du dossier prévu "
                    "(ex. '../../etc/passwd')."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    ssrf_ssti_visitor = _SsrfSstiVisitor()
    ssrf_ssti_visitor.visit(tree)

    for node, symbol in ssrf_ssti_visitor.ssti_hits:
        findings.append(
            Finding(
                rule_id="NIA-SSTI-001",
                cwe="CWE-1336",
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                message="Template Jinja2 construit dynamiquement — risque de Server-Side Template Injection (SSTI).",
                explanation=(
                    "Un template construit par concaténation ou f-string avec une "
                    "entrée non fiable permet à un attaquant d'injecter des "
                    "expressions Jinja2 exécutées côté serveur, pouvant mener à une "
                    "exécution de code arbitraire (RCE)."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    for node, symbol in ssrf_ssti_visitor.ssrf_hits:
        findings.append(
            Finding(
                rule_id="NIA-SSRF-002",
                cwe="CWE-918",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                message="Requête HTTP (requests) potentiellement construite dynamiquement — risque SSRF.",
                explanation=(
                    "L'URL de la requête est assemblée par concaténation ou f-string. "
                    "Si une partie vient d'une entrée utilisateur, un attaquant "
                    "pourrait forcer le serveur à contacter une ressource interne."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    for node, symbol in ssrf_ssti_visitor.verify_false_hits:
        findings.append(
            Finding(
                rule_id="NIA-TLS-003",
                cwe="CWE-295",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                message="requests appelé avec verify=False — vérification de certificat TLS désactivée.",
                explanation=(
                    "Désactiver verify expose à une attaque man-in-the-middle. Notez "
                    "que la bibliothèque requests a eu un bug connu (CVE-2024-35195) "
                    "où ce réglage restait actif de façon persistante sur une Session."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    open_redirect_visitor = _OpenRedirectVisitor()
    open_redirect_visitor.visit(tree)
    for node, symbol in open_redirect_visitor.hits:
        findings.append(
            Finding(
                rule_id="NIA-REDIRECT-001",
                cwe="CWE-601",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                message="redirect() avec une valeur non littérale — risque d'Open Redirect.",
                explanation=(
                    "Si l'URL de redirection vient d'une entrée utilisateur non "
                    "validée, un attaquant peut rediriger vers un site malveillant "
                    "en abusant de la confiance dans le domaine d'origine."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    advanced_visitor = _AdvancedPatternVisitor()
    advanced_visitor.visit(tree)

    for node, symbol in advanced_visitor.zip_slip_hits:
        findings.append(
            Finding(
                rule_id="NIA-ZIPSLIP-001",
                cwe="CWE-22",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                message="extractall() sans validation des chemins — risque de Zip Slip.",
                explanation=(
                    "Une archive malveillante peut contenir des chemins comme "
                    "'../../etc/cron.d/evil' qui s'extraient en dehors du dossier "
                    "prévu. Valider chaque chemin membre avant extraction."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    for node, symbol in advanced_visitor.shell_true_hits:
        findings.append(
            Finding(
                rule_id="NIA-CMD-005",
                cwe="CWE-78",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                message="subprocess appelé avec shell=True — risque d'injection de commande.",
                explanation=(
                    "shell=True interprète la commande via un shell, permettant "
                    "l'injection de méta-caractères si une partie de la commande "
                    "vient d'une entrée non fiable."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    for node, symbol in advanced_visitor.jwt_hits:
        findings.append(
            Finding(
                rule_id="NIA-JWT-001",
                cwe="CWE-347",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                message="Vérification JWT désactivée ou algorithme 'none' accepté.",
                explanation=(
                    "Un token JWT non vérifié ou acceptant l'algorithme 'none' peut "
                    "être forgé par un attaquant pour usurper n'importe quelle "
                    "identité (attaque de confusion d'algorithme)."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    for node, symbol in advanced_visitor.xxe_lxml_hits:
        findings.append(
            Finding(
                rule_id="NIA-XXE-002",
                cwe="CWE-611",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                message="XMLParser lxml avec resolve_entities=True — vulnérable au XXE.",
                explanation=(
                    "Autoriser la résolution d'entités externes permet à un attaquant "
                    "de lire des fichiers locaux ou de déclencher des requêtes "
                    "réseau via un document XML malveillant."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    for node, symbol in advanced_visitor.cors_wildcard_hits:
        findings.append(
            Finding(
                rule_id="NIA-CORS-001",
                cwe="CWE-942",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                message="CORS configuré avec origins='*' — autorise n'importe quel site à appeler cette API.",
                explanation=(
                    "Un wildcard CORS permet à n'importe quel site web tiers "
                    "d'effectuer des requêtes vers cette API depuis le navigateur "
                    "d'une victime, un risque accru si l'API gère des données sensibles."
                ),
                proof=_render_node(source, node),
                location=_node_range(node),
                enclosing_symbol=symbol,
                tier="tier1_deterministic",
            )
        )

    for node, symbol in advanced_visitor.ecb_mode_hits:
        findings.append(
            Finding(
                rule_id="NIA-CRYPTO-004",
                cwe="CWE-327",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                message="Chiffrement AES en mode ECB — révèle des motifs dans les données malgré le chiffrement.",
                explanation=(
                    "Le mode ECB chiffre chaque bloc indépendamment, donc des blocs "
                    "identiques en clair produisent des blocs identiques chiffrés "
                    "(effet 'pingouin ECB'). Utiliser AES-GCM ou AES-CBC avec IV aléatoire."
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
