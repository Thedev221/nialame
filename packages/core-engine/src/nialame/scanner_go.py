"""Parser Go — pont vers un petit programme Go compilé (go_parser/parse.go).

Contrairement à Python (module ast natif) et JavaScript (esprima via
Node), l'AST natif de Go (go/ast) n'est pas sérialisable en JSON. Ce
module invoque donc un binaire Go compilé qui fait lui-même
l'extraction des informations utiles (appels de fonction, détection de
concaténation dynamique) et les retourne en JSON — un choix
d'architecture différent des deux autres langages, documenté ici.

NOTE: comme pour JS/TS, le suivi du symbole englobant (fonction
contenante) n'est pas encore implémenté — enclosing_symbol reste None.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from nialame.models import Confidence, Finding, Range, Severity

_GO_BINARY = Path(__file__).resolve().parent.parent.parent / "go_parser" / "parse_go_binary"

_GO_TIMEOUT_SECONDS = 10


class GoParseError(Exception):
    """Levée quand le code Go fourni n'est pas syntaxiquement valide."""


def parse_go_source(source: str) -> dict:
    """Parse une source Go et retourne la liste des sites d'appel détectés.

    Retourne un dict avec une clé 'call_sites' (liste de dicts). Lève
    GoParseError si le code n'est pas un Go valide ou si le binaire
    échoue pour une autre raison.
    """
    if not _GO_BINARY.exists():
        raise GoParseError(
            f"Binaire Go introuvable ({_GO_BINARY}). "
            "Compilez-le avec : cd go_parser && go build -o parse_go_binary parse.go"
        )

    try:
        result = subprocess.run(
            [str(_GO_BINARY)],
            input=source,
            capture_output=True,
            text=True,
            timeout=_GO_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GoParseError(
            f"Le parsing Go a dépassé le délai de {_GO_TIMEOUT_SECONDS}s."
        ) from exc

    if result.returncode != 0:
        try:
            error_payload = json.loads(result.stderr)
            message = error_payload.get("error", result.stderr)
        except json.JSONDecodeError:
            message = result.stderr or "Erreur inconnue du parser Go."
        raise GoParseError(f"Code Go invalide : {message}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GoParseError(f"Sortie du parser Go non-JSON : {exc}") from exc


def _make_go_finding(source: str, call_site: dict, rule_id: str, cwe: str, severity, message: str, explanation: str) -> Finding:
    lines = source.splitlines()
    start_line = call_site["start_line"]
    end_line = call_site["end_line"]
    snippet = "\n".join(lines[start_line - 1:end_line])[:400]

    return Finding(
        rule_id=rule_id,
        cwe=cwe,
        severity=severity,
        confidence=Confidence.MEDIUM,
        message=message,
        explanation=explanation,
        proof=snippet,
        location=Range(
            start_line=start_line,
            start_column=call_site["start_column"],
            end_line=end_line,
            end_column=call_site["end_column"],
        ),
        enclosing_symbol=None,
        tier="tier1_deterministic",
    )

def scan_go_source(source: str) -> list[Finding]:
    """Analyse une source Go et retourne les findings Tier 1."""
    parsed = parse_go_source(source)
    findings: list[Finding] = []

    for call_site in parsed.get("call_sites") or []:
        qualified = call_site["qualified_name"]
        dynamic = call_site["args_are_dynamic"]

        if qualified == "exec.Command" and dynamic:
            findings.append(_make_go_finding(
                source, call_site, "NIA-GO-CMD-001", "CWE-78", Severity.CRITICAL,
                "exec.Command() avec des arguments construits dynamiquement — risque d'injection de commande.",
                "Un ou plusieurs arguments sont assemblés par concaténation. Si une partie vient d'une entrée non fiable, un attaquant peut injecter des paramètres de commande dangereux.",
            ))

        if qualified in {"md5.Sum", "sha1.Sum", "md5.New", "sha1.New"}:
            findings.append(_make_go_finding(
                source, call_site, "NIA-GO-CRYPTO-001", "CWE-327", Severity.MEDIUM,
                "Algorithme de hachage cryptographiquement faible (MD5/SHA-1).",
                "MD5 et SHA-1 sont cryptographiquement cassés — utiliser le package crypto/sha256 ou supérieur.",
            ))

        if qualified == "rand.Intn" or qualified == "rand.Int":
            findings.append(_make_go_finding(
                source, call_site, "NIA-GO-RANDOM-001", "CWE-330", Severity.HIGH,
                "math/rand utilisé — générateur non cryptographique.",
                "Le package math/rand n'est pas prévu pour un usage sécuritaire. Utiliser crypto/rand pour générer des tokens ou secrets.",
            ))

        if qualified in {"tls.Config", "http.Transport"} and dynamic:
            findings.append(_make_go_finding(
                source, call_site, "NIA-GO-TLS-001", "CWE-295", Severity.HIGH,
                "Configuration TLS potentiellement non sûre.",
                "Vérifiez que InsecureSkipVerify n'est pas activé à true, ce qui désactiverait la vérification de certificat TLS.",
            ))

        if qualified == "gob.NewDecoder" or qualified == "Decode":
            findings.append(_make_go_finding(
                source, call_site, "NIA-GO-DESER-001", "CWE-502", Severity.HIGH,
                "Désérialisation encoding/gob sur une donnée potentiellement non fiable.",
                "encoding/gob peut désérialiser des types arbitraires — vérifiez que la source de données est fiable.",
            ))

    return findings
