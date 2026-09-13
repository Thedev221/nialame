"""Parser JavaScript/TypeScript — pont vers esprima via un sous-processus Node.

Ce module ne réimplémente aucune logique d'analyse en JS : il invoque un
petit script Node (js_parser/parse.js) qui fait uniquement du parsing,
et retourne une structure Python exploitable de façon équivalente à ce
que ast.parse() fait pour Python.

Aucune détection de vulnérabilité n'est encore branchée ici — ce module
pose seulement la fondation du parsing (T1.2). Les règles JS/TS
viendront dans une étape suivante (T1.3), une fois cette base validée.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from nialame.models import Confidence, Finding, Range, Severity

_PARSE_SCRIPT = Path(__file__).resolve().parent.parent.parent / "js_parser" / "parse.js"

_NODE_TIMEOUT_SECONDS = 10


class JsParseError(Exception):
    """Levée quand le code JS/TS fourni n'est pas syntaxiquement valide."""


def parse_javascript_source(source: str) -> dict:
    """Parse une source JavaScript/TypeScript et retourne son AST (format ESTree).

    Lève JsParseError si la source n'est pas un JS valide, ou si le
    sous-processus Node échoue pour une autre raison (timeout, node
    introuvable, etc.) — dans tous ces cas l'appelant doit gérer l'erreur
    proprement, jamais laisser planter silencieusement l'analyse.
    """
    try:
        result = subprocess.run(
            ["node", str(_PARSE_SCRIPT)],
            input=source,
            capture_output=True,
            text=True,
            timeout=_NODE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise JsParseError(
            "Node.js introuvable — requis pour l'analyse JavaScript/TypeScript."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise JsParseError(
            f"Le parsing JS/TS a dépassé le délai de {_NODE_TIMEOUT_SECONDS}s."
        ) from exc

    if result.returncode != 0:
        try:
            error_payload = json.loads(result.stderr)
            message = error_payload.get("error", result.stderr)
        except json.JSONDecodeError:
            message = result.stderr or "Erreur inconnue du parser JS."
        raise JsParseError(f"Code JavaScript/TypeScript invalide : {message}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise JsParseError(f"Sortie du parser JS non-JSON : {exc}") from exc
_SECRET_NAME_HINTS_JS = re.compile(
    r"(?i)^(?:.*_)?(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)s?$"
)


def _walk_estree(node):
    """Parcourt récursivement l'arbre ESTree (dicts/listes imbriqués)."""
    if isinstance(node, dict):
        yield node
        for key, value in node.items():
            if key in ("loc", "range"):
                continue
            yield from _walk_estree(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_estree(item)


def _get_qualified_member_name(node: dict) -> str | None:
    """Pour un CallExpression, retourne 'objet.propriete' ou le nom simple."""
    callee = node.get("callee")
    if not isinstance(callee, dict):
        return None
    if callee.get("type") == "Identifier":
        return callee.get("name")
    if callee.get("type") == "MemberExpression":
        obj = callee.get("object")
        prop = callee.get("property")
        obj_name = obj.get("name") if isinstance(obj, dict) else None
        prop_name = prop.get("name") if isinstance(prop, dict) else None
        if obj_name and prop_name:
            return f"{obj_name}.{prop_name}"
    return None

def _get_call_property_name(node: dict) -> str | None:
    """Retourne juste le nom de propriété d'un appel (ex. 'query' pour
    n'importe quel objet.query()), sans exiger de connaître le nom exact
    de l'objet — utile quand le nom de la variable (db, pool, conn...) varie."""
    callee = node.get("callee")
    if isinstance(callee, dict) and callee.get("type") == "MemberExpression":
        prop = callee.get("property")
        if isinstance(prop, dict):
            return prop.get("name")
    return None
def _is_dynamic_js_value(node) -> bool:
    """Détecte une concaténation (+) ou un template literal avec interpolation."""
    if not isinstance(node, dict):
        return False
    if node.get("type") == "BinaryExpression" and node.get("operator") == "+":
        return True
    if node.get("type") == "TemplateLiteral" and node.get("expressions"):
        return True
    return False


def _node_proof_js(source: str, node: dict) -> str:
    rng = node.get("range")
    if rng and len(rng) == 2:
        return source[rng[0]:rng[1]][:400]
    return ""


def _node_range_js(node: dict) -> Range:
    loc = node.get("loc") or {}
    start = loc.get("start", {"line": 1, "column": 0})
    end = loc.get("end", {"line": start.get("line", 1), "column": start.get("column", 0) + 1})
    return Range(
        start_line=start.get("line", 1),
        start_column=start.get("column", 0),
        end_line=end.get("line", start.get("line", 1)),
        end_column=end.get("column", start.get("column", 0) + 1),
    )


def _make_js_finding(source: str, node: dict, rule_id: str, cwe: str, severity, message: str, explanation: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        cwe=cwe,
        severity=severity,
        confidence=Confidence.MEDIUM,
        message=message,
        explanation=explanation,
        proof=_node_proof_js(source, node),
        location=_node_range_js(node),
        enclosing_symbol=None,
        tier="tier1_deterministic",
    )


def scan_javascript_source(source: str) -> list[Finding]:
    """Analyse une source JavaScript/TypeScript et retourne les findings Tier 1.

    NOTE: ne fait pas encore le suivi du symbole englobant (fonction
    contenante) — limitation connue, comme les alias d'import côté
    Python. enclosing_symbol reste None pour ce premier lot de règles.
    """
    tree = parse_javascript_source(source)
    findings: list[Finding] = []

    for node in _walk_estree(tree):
        node_type = node.get("type")

        if node_type in ("CallExpression", "NewExpression"):
            qualified = _get_qualified_member_name(node)
            args = node.get("arguments", [])

            if qualified in {"eval", "Function"}:
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-EVAL-001", "CWE-95", Severity.CRITICAL,
                    "Exécution de code dynamique via eval()/Function() — dangereux sur une entrée non fiable.",
                    "eval() et le constructeur Function() exécutent du texte comme du code JavaScript. Si ce texte vient d'une entrée utilisateur, un attaquant peut exécuter du code arbitraire.",
                ))

            if qualified == "child_process.exec" and args and _is_dynamic_js_value(args[0]):
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-CMD-001", "CWE-78", Severity.CRITICAL,
                    "child_process.exec() avec une commande construite dynamiquement — risque d'injection de commande.",
                    "La commande est assemblée par concaténation ou template literal. Si une partie vient d'une entrée non fiable, un attaquant peut injecter des commandes shell.",
                ))

            if qualified == "document.write" and args and _is_dynamic_js_value(args[0]):
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-XSS-002", "CWE-79", Severity.HIGH,
                    "document.write() avec un contenu construit dynamiquement — risque de XSS.",
                    "Le contenu écrit est assemblé dynamiquement. Si une partie vient d'une entrée utilisateur, un attaquant peut injecter du HTML/JavaScript malveillant.",
                ))

            if qualified == "crypto.createHash" and args:
                first_arg = args[0]
                if first_arg.get("type") == "Literal" and str(first_arg.get("value", "")).lower() in {"md5", "sha1"}:
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-CRYPTO-001", "CWE-327", Severity.MEDIUM,
                        "Algorithme de hachage cryptographiquement faible (MD5/SHA-1).",
                        "MD5 et SHA-1 sont cryptographiquement cassés — utiliser SHA-256 ou supérieur.",
                    ))

            if qualified == "jwt.verify" and args:
                for arg in args:
                    if arg.get("type") == "ObjectExpression":
                        for prop in arg.get("properties", []):
                            key = prop.get("key", {})
                            if key.get("name") == "algorithms":
                                value = prop.get("value", {})
                                if value.get("type") == "ArrayExpression":
                                    for elt in value.get("elements", []):
                                        if elt.get("type") == "Literal" and str(elt.get("value", "")).lower() == "none":
                                            findings.append(_make_js_finding(
                                                source, node, "NIA-JS-JWT-001", "CWE-347", Severity.CRITICAL,
                                                "jwt.verify accepte l'algorithme 'none' — vérification de signature contournable.",
                                                "Accepter l'algorithme 'none' permet à un attaquant de forger un token JWT valide sans connaître la clé secrète.",
                                            ))

            if qualified == "require" and args:
                if args[0].get("type") != "Literal":
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-IMPORT-001", "CWE-829", Severity.HIGH,
                        "require() avec un nom de module non littéral — import dynamique dangereux.",
                        "Si le nom du module vient d'une entrée non fiable, un attaquant peut forcer le chargement d'un module arbitraire.",
                    ))

            if qualified in {"fs.readFile", "fs.readFileSync", "fs.writeFile", "fs.writeFileSync"} and args:
                if _is_dynamic_js_value(args[0]):
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-PATH-001", "CWE-22", Severity.HIGH,
                        "Chemin de fichier construit dynamiquement — risque de Path Traversal.",
                        "Le chemin est assemblé par concaténation ou template literal. Si une partie vient d'une entrée utilisateur, un attaquant pourrait accéder à des fichiers hors du dossier prévu.",
                    ))

        if node_type == "AssignmentExpression":
            left = node.get("left", {})
            if left.get("type") == "MemberExpression" and left.get("property", {}).get("name") == "innerHTML":
                right = node.get("right", {})
                if right.get("type") != "Literal":
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-XSS-001", "CWE-79", Severity.HIGH,
                        "Assignation à innerHTML avec une valeur non littérale — risque de XSS.",
                        "innerHTML n'échappe pas le HTML. Si la valeur assignée vient d'une entrée utilisateur, un attaquant peut injecter du HTML/JavaScript malveillant.",
                    ))

        if node_type == "VariableDeclarator":
            id_node = node.get("id", {})
            init_node = node.get("init")
            if id_node.get("type") == "Identifier" and _SECRET_NAME_HINTS_JS.match(id_node.get("name", "")):
                if isinstance(init_node, dict):
                    if init_node.get("type") == "Literal" and isinstance(init_node.get("value"), str):
                        findings.append(_make_js_finding(
                            source, node, "NIA-JS-SECRET-001", "CWE-798", Severity.CRITICAL,
                            "Secret potentiellement codé en dur dans le code source.",
                            "Une variable au nom évocateur d'un secret est assignée à une chaîne littérale. Utilisez une variable d'environnement ou un gestionnaire de secrets.",
                        ))
                    elif (
                        init_node.get("type") == "CallExpression"
                        and _get_qualified_member_name(init_node) == "Math.random"
                    ):
                        findings.append(_make_js_finding(
                            source, node, "NIA-JS-RANDOM-001", "CWE-330", Severity.HIGH,
                            "Math.random() utilisé pour une valeur sensible — générateur non cryptographique.",
                            "Math.random() n'est pas prévu pour un usage sécuritaire — utilisez crypto.randomBytes() à la place.",
                        ))


        if node_type in ("CallExpression", "NewExpression"):
            prop_name = _get_call_property_name(node)
            args = node.get("arguments", [])

            if prop_name == "query" and args and _is_dynamic_js_value(args[0]):
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-SQLI-001", "CWE-89", Severity.CRITICAL,
                    "Requête SQL potentiellement construite par concaténation dynamique.",
                    "L'argument de .query() est assemblé par concaténation ou template literal. Utilisez des requêtes paramétrées (placeholders ?) au lieu d'interpoler directement.",
                ))

            if prop_name in {"spawn", "execSync"}:
                for kw in args:
                    if kw.get("type") == "ObjectExpression":
                        for prop in kw.get("properties", []):
                            if (
                                prop.get("key", {}).get("name") == "shell"
                                and prop.get("value", {}).get("value") is True
                            ):
                                findings.append(_make_js_finding(
                                    source, node, "NIA-JS-CMD-002", "CWE-78", Severity.CRITICAL,
                                    "child_process appelé avec shell: true — risque d'injection de commande.",
                                    "shell: true interprète la commande via un shell, permettant l'injection de méta-caractères si une partie vient d'une entrée non fiable.",
                                ))
                if args and _is_dynamic_js_value(args[0]):
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-CMD-002", "CWE-78", Severity.CRITICAL,
                        "Commande shell construite dynamiquement.",
                        "La commande est assemblée par concaténation ou template literal — risque d'injection si une partie vient d'une entrée non fiable.",
                    ))

            if _get_qualified_member_name(node) == "node-serialize.unserialize" or prop_name == "unserialize":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-DESER-001", "CWE-502", Severity.CRITICAL,
                    "Désérialisation non sûre via node-serialize — RCE connue et documentée.",
                    "Le package node-serialize permet d'exécuter du code arbitraire via un objet JSON spécialement conçu passé à unserialize().",
                ))

            if prop_name == "redirect" and args and args[0].get("type") != "Literal":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-REDIRECT-001", "CWE-601", Severity.MEDIUM,
                    "res.redirect() avec une valeur non littérale — risque d'Open Redirect.",
                    "Si l'URL de redirection vient d'une entrée utilisateur non validée, un attaquant peut rediriger vers un site malveillant.",
                ))

            if prop_name == "parseXml":
                for kw in args:
                    if kw.get("type") == "ObjectExpression":
                        for prop in kw.get("properties", []):
                            if (
                                prop.get("key", {}).get("name") == "noent"
                                and prop.get("value", {}).get("value") is True
                            ):
                                findings.append(_make_js_finding(
                                    source, node, "NIA-JS-XXE-001", "CWE-611", Severity.HIGH,
                                    "parseXml appelé avec noent: true — vulnérable au XXE.",
                                    "Autoriser la résolution d'entités externes permet à un attaquant de lire des fichiers locaux via un document XML malveillant.",
                                ))

            if prop_name == "sign" and args and len(args) >= 2:
                secret_arg = args[1]
                if secret_arg.get("type") == "Literal" and isinstance(secret_arg.get("value"), str):
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-JWT-002", "CWE-798", Severity.CRITICAL,
                        "jwt.sign() avec un secret codé en dur.",
                        "Le secret de signature JWT est une chaîne littérale dans le code source. Utilisez une variable d'environnement.",
                    ))

            if prop_name == "extractAllTo":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-ZIPSLIP-001", "CWE-22", Severity.HIGH,
                    "extractAllTo() sans validation des chemins — risque de Zip Slip.",
                    "Une archive malveillante peut contenir des chemins qui s'extraient en dehors du dossier prévu. Valider chaque chemin membre avant extraction.",
                ))

        if node_type == "Property":
            key = node.get("key", {})
            if key.get("name") == "$where" or (key.get("type") == "Literal" and key.get("value") == "$where"):
                value = node.get("value", {})
                if _is_dynamic_js_value(value) or value.get("type") == "Identifier":
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-NOSQL-001", "CWE-943", Severity.CRITICAL,
                        "$where MongoDB avec une valeur potentiellement dynamique — risque d'injection NoSQL.",
                        "$where exécute du JavaScript côté serveur MongoDB. Si la valeur vient d'une entrée non fiable, un attaquant peut injecter du code arbitraire.",
                    ))

        if node_type == "MemberExpression":
            prop = node.get("property", {})
            computed = node.get("computed", False)
            if computed and prop.get("type") == "Literal" and prop.get("value") == "__proto__":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-PROTO-001", "CWE-1321", Severity.HIGH,
                    "Accès à __proto__ via une clé dynamique — risque de Prototype Pollution.",
                    "Modifier __proto__ via une clé calculée dynamiquement (souvent depuis une entrée utilisateur, ex. JSON.parse) peut altérer le comportement de tous les objets de l'application.",
                ))

        if node_type == "Literal" and isinstance(node.get("value"), str):
            pass  # réservé pour une future règle sur les cookies (voir note ci-dessous)

    return findings
