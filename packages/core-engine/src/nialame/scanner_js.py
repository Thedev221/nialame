"""Parser JavaScript/TypeScript — pont vers esprima via un sous-processus Node.

Ce module ne réimplémente aucune logique d'analyse en JS : il invoque un
petit script Node (js_parser/parse.js) qui fait uniquement du parsing,
et retourne une structure Python exploitable de façon équivalente à ce
que ast.parse() fait pour Python.

NOTE: ne fait pas encore le suivi du symbole englobant (fonction
contenante) — limitation connue, comme les alias d'import côté Python.
enclosing_symbol reste None pour toutes les règles JS/TS.
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
    introuvable, etc.).
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
    """Pour un CallExpression/NewExpression, retourne 'objet.propriete' ou le nom simple."""
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
    """Analyse une source JavaScript/TypeScript et retourne les findings Tier 1."""
    tree = parse_javascript_source(source)
    findings: list[Finding] = []

    for node in _walk_estree(tree):
        node_type = node.get("type")

        if node_type in ("CallExpression", "NewExpression"):
            qualified = _get_qualified_member_name(node)
            prop_name = _get_call_property_name(node)
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

            if prop_name == "cookie" and args:
                options = args[2] if len(args) >= 3 else None
                http_only_ok = False
                secure_ok = False
                if isinstance(options, dict) and options.get("type") == "ObjectExpression":
                    for prop in options.get("properties", []):
                        key_name = prop.get("key", {}).get("name") or prop.get("key", {}).get("value")
                        value_node = prop.get("value", {})
                        if key_name == "httpOnly" and value_node.get("value") is True:
                            http_only_ok = True
                        if key_name == "secure" and value_node.get("value") is True:
                            secure_ok = True
                if not (http_only_ok and secure_ok):
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-COOKIE-001", "CWE-614", Severity.MEDIUM,
                        "Cookie posé sans httpOnly et/ou secure activés.",
                        "Sans httpOnly, le cookie est accessible en JavaScript (risque de vol via XSS). Sans secure, il peut être transmis en clair sur HTTP.",
                    ))

            if qualified == "cors" and args:
                for kw in args:
                    if kw.get("type") == "ObjectExpression":
                        for prop in kw.get("properties", []):
                            if prop.get("key", {}).get("name") == "origin" and prop.get("value", {}).get("value") == "*":
                                findings.append(_make_js_finding(
                                    source, node, "NIA-JS-CORS-001", "CWE-942", Severity.MEDIUM,
                                    "CORS configuré avec origin: '*' — autorise n'importe quel site à appeler cette API.",
                                    "Un wildcard CORS permet à n'importe quel site tiers d'effectuer des requêtes vers cette API depuis le navigateur d'une victime.",
                                ))

            if prop_name == "setHeader" and len(args) >= 2:
                header_name = args[0]
                header_value = args[1]
                if (
                    header_name.get("type") == "Literal"
                    and str(header_name.get("value", "")).lower() == "access-control-allow-origin"
                    and header_value.get("type") == "Literal"
                    and header_value.get("value") == "*"
                ):
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-CORS-001", "CWE-942", Severity.MEDIUM,
                        "En-tête Access-Control-Allow-Origin fixé à '*' — autorise n'importe quel site à appeler cette API.",
                        "Un wildcard CORS permet à n'importe quel site tiers d'effectuer des requêtes vers cette API depuis le navigateur d'une victime.",
                    ))
                elif header_value.get("type") != "Literal":
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-HEADER-001", "CWE-93", Severity.MEDIUM,
                        "setHeader() avec une valeur construite dynamiquement — risque d'injection d'en-tête HTTP (CRLF).",
                        "Si la valeur de l'en-tête vient d'une entrée non fiable, un attaquant peut injecter des sauts de ligne pour forger des en-têtes ou une réponse HTTP supplémentaire.",
                    ))

            for arg in args:
                if arg.get("type") == "ObjectExpression":
                    for prop in arg.get("properties", []):
                        if (
                            prop.get("key", {}).get("name") == "rejectUnauthorized"
                            and prop.get("value", {}).get("value") is False
                        ):
                            findings.append(_make_js_finding(
                                source, node, "NIA-JS-TLS-001", "CWE-295", Severity.HIGH,
                                "rejectUnauthorized: false — vérification de certificat TLS désactivée.",
                                "Désactiver rejectUnauthorized expose à une attaque man-in-the-middle : n'importe quel certificat, même invalide, sera accepté.",
                            ))

            if qualified in {"vm.runInNewContext", "vm.runInThisContext", "vm.runInContext"}:
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-VM-001", "CWE-95", Severity.CRITICAL,
                    "Exécution de code dynamique via le module vm — dangereux sur une entrée non fiable.",
                    "Le module vm de Node.js n'est PAS un sandbox de sécurité fiable — du code malveillant peut s'en échapper.",
                ))

            if qualified == "yaml.load":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-YAML-001", "CWE-502", Severity.HIGH,
                    "yaml.load() (js-yaml) sans schéma sûr — désérialisation potentiellement dangereuse.",
                    "Les versions de js-yaml antérieures à la v4 pouvaient exécuter du code arbitraire via des tags YAML spéciaux avec load(). Vérifier la version ou utiliser un schema sûr.",
                ))

            if qualified in {"_.template", "ejs.render", "ejs.compile"} and args and _is_dynamic_js_value(args[0]):
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-SSTI-001", "CWE-1336", Severity.CRITICAL,
                    "Template construit dynamiquement — risque de Server-Side Template Injection (SSTI).",
                    "Un template assemblé par concaténation ou template literal avec une entrée non fiable permet d'injecter des expressions exécutées côté serveur.",
                ))

            if prop_name in {"json", "send"} and args:
                first = args[0]
                if isinstance(first, dict) and first.get("type") == "MemberExpression":
                    obj = first.get("object", {})
                    prop = first.get("property", {})
                    if obj.get("name") == "process" and prop.get("name") == "env":
                        findings.append(_make_js_finding(
                            source, node, "NIA-JS-EXPOSE-001", "CWE-200", Severity.HIGH,
                            "process.env envoyé directement au client — fuite potentielle de secrets d'environnement.",
                            "process.env contient souvent des secrets (clés API, mots de passe). L'envoyer tel quel au client les expose publiquement.",
                        ))

            if qualified in {"http.get", "https.get", "axios.get", "axios.post", "axios.put", "axios.delete", "fetch"} and args and _is_dynamic_js_value(args[0]):
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-SSRF-001", "CWE-918", Severity.MEDIUM,
                    "Requête HTTP potentiellement construite dynamiquement — risque SSRF.",
                    "L'URL de la requête est assemblée dynamiquement. Si une partie vient d'une entrée utilisateur, un attaquant pourrait forcer le serveur à contacter une ressource interne.",
                ))

            if qualified == "Object.assign" and len(args) >= 2:
                second = args[1]
                if isinstance(second, dict) and second.get("type") == "MemberExpression" and second.get("property", {}).get("name") == "body":
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-MASSASSIGN-001", "CWE-915", Severity.HIGH,
                        "Object.assign() avec req.body directement — risque de Mass Assignment.",
                        "Fusionner req.body sans filtrage permet à un attaquant d'écraser des champs non prévus via des clés supplémentaires dans la requête.",
                    ))

            if qualified == "crypto.createCipher":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-CRYPTO-002", "CWE-327", Severity.MEDIUM,
                    "crypto.createCipher() est déprécié et cryptographiquement faible.",
                    "Utiliser crypto.createCipheriv() avec une clé et un IV générés de façon sécurisée à la place.",
                ))

            if qualified in {"path.join", "path.resolve"} and any(a.get("type") != "Literal" for a in args):
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-PATH-002", "CWE-22", Severity.HIGH,
                    "path.join()/path.resolve() avec un segment construit dynamiquement — risque de Path Traversal.",
                    "Si un segment du chemin vient d'une entrée utilisateur non validée, un attaquant peut utiliser '../' pour sortir du dossier prévu.",
                ))

            if qualified == "Buffer":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-BUFFER-001", "CWE-908", Severity.MEDIUM,
                    "Constructeur Buffer() déprécié et potentiellement non sûr (mémoire non initialisée).",
                    "Utiliser Buffer.alloc(), Buffer.from() ou Buffer.allocUnsafe() en toute connaissance de cause à la place.",
                ))

            if qualified == "session" and args:
                for arg in args:
                    if arg.get("type") == "ObjectExpression":
                        for prop in arg.get("properties", []):
                            value_node = prop.get("value", {})
                            if (
                                prop.get("key", {}).get("name") == "secret"
                                and value_node.get("type") == "Literal"
                                and isinstance(value_node.get("value"), str)
                            ):
                                findings.append(_make_js_finding(
                                    source, node, "NIA-JS-SESSION-001", "CWE-798", Severity.CRITICAL,
                                    "Secret de session (express-session) codé en dur.",
                                    "Un secret de session en clair dans le code source permet à quiconque y a accès de forger des sessions valides. Utiliser une variable d'environnement.",
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

        if node_type == "BinaryExpression" and node.get("operator") in ("===", "=="):
            left = node.get("left", {})
            right = node.get("right", {})
            for operand in (left, right):
                if isinstance(operand, dict) and operand.get("type") == "Identifier" and _SECRET_NAME_HINTS_JS.match(operand.get("name", "")):
                    findings.append(_make_js_finding(
                        source, node, "NIA-JS-TIMING-001", "CWE-208", Severity.MEDIUM,
                        "Comparaison directe (===) d'une valeur sensible — vulnérable à une attaque temporelle.",
                        "Comparer un secret avec === peut fuiter sa valeur via le temps de réponse. Utiliser crypto.timingSafeEqual() à la place.",
                    ))
                    break

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

            if key.get("name") == "dangerouslySetInnerHTML":
                value = node.get("value", {})
                if value.get("type") == "ObjectExpression":
                    for inner in value.get("properties", []):
                        inner_key = inner.get("key", {})
                        inner_value = inner.get("value", {})
                        if inner_key.get("name") == "__html" and inner_value.get("type") != "Literal":
                            findings.append(_make_js_finding(
                                source, node, "NIA-JS-DANGERHTML-001", "CWE-79", Severity.HIGH,
                                "dangerouslySetInnerHTML avec une valeur __html non littérale — risque de XSS.",
                                "React n'échappe pas le contenu passé à dangerouslySetInnerHTML. Si la valeur vient d'une entrée utilisateur, un attaquant peut injecter du HTML/JavaScript malveillant.",
                            ))

        if node_type == "MemberExpression":
            prop = node.get("property", {})
            computed = node.get("computed", False)
            if computed and prop.get("type") == "Literal" and prop.get("value") == "__proto__":
                findings.append(_make_js_finding(
                    source, node, "NIA-JS-PROTO-001", "CWE-1321", Severity.HIGH,
                    "Accès à __proto__ via une clé dynamique — risque de Prototype Pollution.",
                    "Modifier __proto__ via une clé calculée dynamiquement peut altérer le comportement de tous les objets de l'application.",
                ))

    return findings
