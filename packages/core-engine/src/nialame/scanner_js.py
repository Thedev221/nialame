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
import subprocess
from pathlib import Path

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
