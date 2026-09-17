"""Parser Go — pont vers un petit programme Go compilé (go_parser/parse.go).

Contrairement à Python (module ast natif) et JavaScript (esprima via
Node), l'AST natif de Go (go/ast) n'est pas sérialisable en JSON. Ce
module invoque donc un binaire Go compilé qui fait lui-même
l'extraction des informations utiles (appels de fonction, détection de
concaténation dynamique) et les retourne en JSON.

LIMITATIONS CONNUES (à affiner dans une itération future) :
- Le parseur n'extrait que les appels de fonction : ni les assignations,
  ni les structures littérales. Certaines règles sont donc plus larges
  que leurs équivalents Python/JS (ex. TLS : on signale la présence
  d'une config sans vérifier la valeur d'InsecureSkipVerify).
- Le suivi du symbole englobant n'est pas implémenté : enclosing_symbol
  reste None, comme pour JS/TS.
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
    """Parse une source Go et retourne la liste des sites d'appel détectés."""
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


# Règles simples : nom d'appel qualifié -> (rule_id, cwe, severity, message, explanation)
_GO_SIMPLE_RULES: dict[str, tuple] = {
    "md5.Sum": ("NIA-GO-CRYPTO-001", "CWE-327", Severity.MEDIUM,
        "Algorithme de hachage cryptographiquement faible (MD5).",
        "MD5 est cryptographiquement cassé — utiliser crypto/sha256 ou supérieur."),
    "md5.New": ("NIA-GO-CRYPTO-001", "CWE-327", Severity.MEDIUM,
        "Algorithme de hachage cryptographiquement faible (MD5).",
        "MD5 est cryptographiquement cassé — utiliser crypto/sha256 ou supérieur."),
    "sha1.Sum": ("NIA-GO-CRYPTO-001", "CWE-327", Severity.MEDIUM,
        "Algorithme de hachage cryptographiquement affaibli (SHA-1).",
        "SHA-1 est cryptographiquement affaibli — utiliser crypto/sha256 ou supérieur."),
    "sha1.New": ("NIA-GO-CRYPTO-001", "CWE-327", Severity.MEDIUM,
        "Algorithme de hachage cryptographiquement affaibli (SHA-1).",
        "SHA-1 est cryptographiquement affaibli — utiliser crypto/sha256 ou supérieur."),
    "rand.Intn": ("NIA-GO-RANDOM-001", "CWE-330", Severity.HIGH,
        "math/rand utilisé — générateur non cryptographique.",
        "Le package math/rand n'est pas prévu pour un usage sécuritaire. Utiliser crypto/rand pour générer des tokens ou secrets."),
    "rand.Int": ("NIA-GO-RANDOM-001", "CWE-330", Severity.HIGH,
        "math/rand utilisé — générateur non cryptographique.",
        "Le package math/rand n'est pas prévu pour un usage sécuritaire. Utiliser crypto/rand pour générer des tokens ou secrets."),
    "rand.Seed": ("NIA-GO-RANDOM-002", "CWE-335", Severity.MEDIUM,
        "rand.Seed() — graine potentiellement prévisible.",
        "Semer math/rand (souvent avec l'horodatage) produit une séquence prévisible. Utiliser crypto/rand pour tout usage sécuritaire."),
    "des.NewCipher": ("NIA-GO-CRYPTO-002", "CWE-327", Severity.MEDIUM,
        "DES est un algorithme de chiffrement cryptographiquement cassé.",
        "Utiliser crypto/aes avec un mode authentifié (GCM) à la place."),
    "des.NewTripleDESCipher": ("NIA-GO-CRYPTO-002", "CWE-327", Severity.MEDIUM,
        "Triple DES est un algorithme de chiffrement obsolète.",
        "Utiliser crypto/aes avec un mode authentifié (GCM) à la place."),
    "rc4.NewCipher": ("NIA-GO-CRYPTO-002", "CWE-327", Severity.MEDIUM,
        "RC4 est un algorithme de chiffrement cryptographiquement cassé.",
        "Utiliser crypto/aes avec un mode authentifié (GCM) à la place."),
    "md4.New": ("NIA-GO-CRYPTO-003", "CWE-327", Severity.MEDIUM,
        "MD4 est un algorithme de hachage totalement cassé.",
        "MD4 est cassé depuis des décennies — utiliser crypto/sha256 ou supérieur."),
    "ripemd160.New": ("NIA-GO-CRYPTO-003", "CWE-327", Severity.LOW,
        "RIPEMD-160 est un algorithme de hachage légataire.",
        "Préférer crypto/sha256 pour tout nouvel usage."),
    "gob.NewDecoder": ("NIA-GO-DESER-001", "CWE-502", Severity.HIGH,
        "Désérialisation encoding/gob sur une donnée potentiellement non fiable.",
        "encoding/gob peut désérialiser des types arbitraires — vérifiez que la source de données est fiable."),
    "yaml.Unmarshal": ("NIA-GO-YAML-001", "CWE-502", Severity.MEDIUM,
        "Désérialisation YAML — vérifier que la source est fiable.",
        "Désérialiser du YAML non fiable dans une structure permissive peut mener à des comportements inattendus. Valider le schéma attendu."),
    "xml.Unmarshal": ("NIA-GO-XXE-001", "CWE-611", Severity.MEDIUM,
        "Parsing XML — vérifier l'absence de résolution d'entités externes (XXE).",
        "Le parseur XML de Go ne résout pas les entités externes par défaut, mais vérifiez qu'aucun décodeur personnalisé ne le réactive."),
    "xml.NewDecoder": ("NIA-GO-XXE-001", "CWE-611", Severity.MEDIUM,
        "Décodeur XML — vérifier l'absence de résolution d'entités externes (XXE).",
        "Vérifiez que le champ Entity du décodeur n'est pas alimenté par une source non fiable."),
    "plugin.Open": ("NIA-GO-PLUGIN-001", "CWE-829", Severity.CRITICAL,
        "Chargement dynamique de plugin — exécution de code arbitraire si le chemin est contrôlable.",
        "plugin.Open charge et exécute du code compilé. Si le chemin vient d'une entrée non fiable, un attaquant peut exécuter du code arbitraire."),
    "template.HTML": ("NIA-GO-TEMPLATE-001", "CWE-79", Severity.HIGH,
        "template.HTML contourne l'échappement automatique — risque de XSS.",
        "Convertir une chaîne en template.HTML désactive la protection XSS de html/template. Ne jamais l'appliquer à une entrée utilisateur."),
    "template.JS": ("NIA-GO-TEMPLATE-001", "CWE-79", Severity.HIGH,
        "template.JS contourne l'échappement automatique — risque de XSS.",
        "Convertir une chaîne en template.JS désactive la protection de html/template. Ne jamais l'appliquer à une entrée utilisateur."),
    "ssh.InsecureIgnoreHostKey": ("NIA-GO-SSH-001", "CWE-295", Severity.HIGH,
        "InsecureIgnoreHostKey accepte n'importe quelle clé d'hôte SSH.",
        "Expose à une attaque man-in-the-middle : le serveur SSH n'est pas authentifié. Utiliser ssh.FixedHostKey ou un known_hosts."),
    "zip.OpenReader": ("NIA-GO-ZIPSLIP-001", "CWE-22", Severity.MEDIUM,
        "Ouverture d'archive ZIP — valider chaque chemin membre avant extraction (Zip Slip).",
        "Une archive malveillante peut contenir des chemins '../' qui s'extraient hors du dossier prévu. Valider chaque nom de fichier avec filepath.Clean et vérifier le préfixe."),
    "tar.NewReader": ("NIA-GO-ZIPSLIP-001", "CWE-22", Severity.MEDIUM,
        "Lecture d'archive TAR — valider chaque chemin membre avant extraction (Zip Slip).",
        "Une archive malveillante peut contenir des chemins '../' qui s'extraient hors du dossier prévu. Valider chaque nom de fichier avant écriture."),
    "os.Chmod": ("NIA-GO-PERM-001", "CWE-732", Severity.LOW,
        "Modification de permissions de fichier — vérifier que les permissions accordées sont bien celles voulues.",
        "Des permissions trop permissives (0777) exposent le fichier à tout utilisateur du système."),
    "os.MkdirAll": ("NIA-GO-PERM-001", "CWE-732", Severity.LOW,
        "Création de répertoire — vérifier les permissions accordées.",
        "Des permissions trop permissives (0777) exposent le répertoire à tout utilisateur du système."),
    "ioutil.TempFile": ("NIA-GO-TMPFILE-001", "CWE-377", Severity.LOW,
        "Création de fichier temporaire — vérifier les permissions et le nettoyage.",
        "Vérifiez que le fichier temporaire est supprimé après usage et qu'il n'est pas lisible par d'autres utilisateurs."),
    "jwt.Parse": ("NIA-GO-JWT-001", "CWE-347", Severity.HIGH,
        "Parsing JWT — vérifier que l'algorithme de signature est explicitement contrôlé.",
        "Sans vérification explicite de la méthode de signature dans la fonction de callback, un attaquant peut exploiter une confusion d'algorithme (ex. 'none' ou HMAC vs RSA)."),
    "jwt.ParseWithClaims": ("NIA-GO-JWT-001", "CWE-347", Severity.HIGH,
        "Parsing JWT — vérifier que l'algorithme de signature est explicitement contrôlé.",
        "Sans vérification explicite de la méthode de signature dans la fonction de callback, un attaquant peut exploiter une confusion d'algorithme."),
    "http.ListenAndServe": ("NIA-GO-LISTEN-001", "CWE-319", Severity.MEDIUM,
        "Serveur HTTP en clair (sans TLS).",
        "ListenAndServe sert le trafic en HTTP non chiffré. Utiliser ListenAndServeTLS en production, ou placer un reverse proxy TLS devant."),
    "unsafe.Pointer": ("NIA-GO-UNSAFE-001", "CWE-119", Severity.MEDIUM,
        "Usage du package unsafe — contourne les garanties de sûreté mémoire de Go.",
        "unsafe.Pointer désactive les vérifications du compilateur et peut mener à des corruptions mémoire. À réserver aux cas strictement nécessaires et bien audités."),
}

# Règles nécessitant un argument construit dynamiquement (concaténation)
_GO_DYNAMIC_RULES: dict[str, tuple] = {
    "exec.Command": ("NIA-GO-CMD-001", "CWE-78", Severity.CRITICAL,
        "exec.Command() avec des arguments construits dynamiquement — risque d'injection de commande.",
        "Un ou plusieurs arguments sont assemblés par concaténation. Si une partie vient d'une entrée non fiable, un attaquant peut injecter des paramètres de commande dangereux."),
    "exec.CommandContext": ("NIA-GO-CMD-002", "CWE-78", Severity.CRITICAL,
        "exec.CommandContext() avec des arguments construits dynamiquement — risque d'injection de commande.",
        "Un ou plusieurs arguments sont assemblés par concaténation. Si une partie vient d'une entrée non fiable, un attaquant peut injecter des paramètres de commande dangereux."),
    "os.Open": ("NIA-GO-PATH-001", "CWE-22", Severity.HIGH,
        "Chemin de fichier construit dynamiquement — risque de Path Traversal.",
        "Le chemin est assemblé par concaténation. Si une partie vient d'une entrée utilisateur, un attaquant pourrait accéder à des fichiers hors du dossier prévu ('../../etc/passwd')."),
    "os.OpenFile": ("NIA-GO-PATH-001", "CWE-22", Severity.HIGH,
        "Chemin de fichier construit dynamiquement — risque de Path Traversal.",
        "Le chemin est assemblé par concaténation. Valider et nettoyer le chemin avec filepath.Clean avant usage."),
    "os.ReadFile": ("NIA-GO-PATH-001", "CWE-22", Severity.HIGH,
        "Chemin de fichier construit dynamiquement — risque de Path Traversal.",
        "Le chemin est assemblé par concaténation. Valider et nettoyer le chemin avec filepath.Clean avant usage."),
    "ioutil.ReadFile": ("NIA-GO-PATH-001", "CWE-22", Severity.HIGH,
        "Chemin de fichier construit dynamiquement — risque de Path Traversal.",
        "Le chemin est assemblé par concaténation. Valider et nettoyer le chemin avec filepath.Clean avant usage."),
    "filepath.Join": ("NIA-GO-PATH-002", "CWE-22", Severity.MEDIUM,
        "filepath.Join() avec un segment construit dynamiquement — risque de Path Traversal.",
        "filepath.Join nettoie le chemin mais ne l'empêche pas de sortir du dossier de base. Vérifier le préfixe du résultat après nettoyage."),
    "http.Get": ("NIA-GO-SSRF-001", "CWE-918", Severity.MEDIUM,
        "Requête HTTP avec une URL construite dynamiquement — risque SSRF.",
        "Si une partie de l'URL vient d'une entrée utilisateur, un attaquant pourrait forcer le serveur à contacter une ressource interne."),
    "http.Post": ("NIA-GO-SSRF-001", "CWE-918", Severity.MEDIUM,
        "Requête HTTP avec une URL construite dynamiquement — risque SSRF.",
        "Si une partie de l'URL vient d'une entrée utilisateur, un attaquant pourrait forcer le serveur à contacter une ressource interne."),
    "http.Redirect": ("NIA-GO-REDIRECT-001", "CWE-601", Severity.MEDIUM,
        "Redirection avec une URL construite dynamiquement — risque d'Open Redirect.",
        "Si l'URL de redirection vient d'une entrée utilisateur non validée, un attaquant peut rediriger vers un site malveillant."),
}

# Suffixes d'appel (le nom de la variable varie : db, tx, conn...)
_GO_SQL_SUFFIXES = (".Query", ".QueryRow", ".QueryContext", ".Exec", ".ExecContext")


def scan_go_source(source: str) -> list[Finding]:
    """Analyse une source Go et retourne les findings Tier 1."""
    parsed = parse_go_source(source)
    findings: list[Finding] = []

    for call_site in parsed.get("call_sites") or []:
        qualified = call_site["qualified_name"]
        dynamic = call_site["args_are_dynamic"]

        rule = _GO_SIMPLE_RULES.get(qualified)
        if rule is not None:
            rule_id, cwe, severity, message, explanation = rule
            findings.append(_make_go_finding(source, call_site, rule_id, cwe, severity, message, explanation))

        if dynamic:
            dyn_rule = _GO_DYNAMIC_RULES.get(qualified)
            if dyn_rule is not None:
                rule_id, cwe, severity, message, explanation = dyn_rule
                findings.append(_make_go_finding(source, call_site, rule_id, cwe, severity, message, explanation))

            if any(qualified.endswith(suffix) for suffix in _GO_SQL_SUFFIXES):
                findings.append(_make_go_finding(
                    source, call_site, "NIA-GO-SQLI-001", "CWE-89", Severity.CRITICAL,
                    "Requête SQL construite par concaténation de chaîne — risque d'injection SQL.",
                    "La requête est assemblée dynamiquement. Utiliser des requêtes paramétrées (placeholders $1/?) plutôt que la concaténation.",
                ))

        if qualified in {"tls.Config", "http.Transport"}:
            findings.append(_make_go_finding(
                source, call_site, "NIA-GO-TLS-001", "CWE-295", Severity.MEDIUM,
                "Configuration TLS personnalisée — vérifier qu'InsecureSkipVerify n'est pas activé.",
                "InsecureSkipVerify: true désactive la vérification de certificat et expose à une attaque man-in-the-middle. (Le parseur Go actuel ne lit pas les valeurs de structure : vérification manuelle requise.)",
            ))

    return findings
