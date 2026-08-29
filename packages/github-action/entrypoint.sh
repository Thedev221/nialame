#!/usr/bin/env bash
# Entrypoint de la GitHub Action Nialame.
#
# Contraintes de sécurité :
# - aucun code source n'est écrit dans les logs ;
# - le LLM n'est jamais utilisé sauf --llm-enabled=true explicite ;
# - échec du job uniquement selon la politique --fail-on.
set -euo pipefail

FAIL_ON="critical"
UPLOAD_SARIF="true"
LLM_ENABLED="false"
PATHS_GLOB="**/*.py"

for arg in "$@"; do
  case "$arg" in
    --fail-on=*) FAIL_ON="${arg#*=}" ;;
    --upload-sarif=*) UPLOAD_SARIF="${arg#*=}" ;;
    --llm-enabled=*) LLM_ENABLED="${arg#*=}" ;;
    --paths=*) PATHS_GLOB="${arg#*=}" ;;
    *) echo "Argument inconnu ignoré: $arg" ;;
  esac
done

echo "Nialame Security Scan — fail-on=${FAIL_ON} llm-enabled=${LLM_ENABLED}"

if [ "${LLM_ENABLED}" != "false" ]; then
  echo "::warning::llm-enabled=true n'est pas encore câblé côté CI dans ce MVP ; le scan reste Tier 1 uniquement."
fi

WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"

python3 - "$WORKSPACE" "$PATHS_GLOB" "$FAIL_ON" <<'PYEOF'
import json
import sys
from pathlib import Path

sys.path.insert(0, "/action/core-engine/src")

from nialame.models import FileReviewResult
from nialame.sarif import build_sarif_report
from nialame.scanner import scan_python_source

workspace = Path(sys.argv[1])
pattern = sys.argv[2]
fail_on = sys.argv[3]

severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
fail_threshold = severity_order.get(fail_on, 4)

results = []
total_findings = 0
worst_severity = -1

for path in sorted(workspace.glob(pattern)):
    if not path.is_file():
        continue
    try:
        source = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    try:
        findings = scan_python_source(source)
    except SyntaxError:
        # Ne jamais faire échouer le job sur un fichier non-Python valide
        # (ex: script généré) ; on journalise seulement le chemin, jamais le code.
        print(f"::warning file={path}::analyse ignorée (syntaxe invalide)")
        continue

    if findings:
        rel_path = str(path.relative_to(workspace))
        results.append(FileReviewResult(file_path=rel_path, findings=findings))
        total_findings += len(findings)
        for f in findings:
            worst_severity = max(worst_severity, severity_order[f.severity.value])

sarif_report = build_sarif_report(results)

sarif_path = workspace / "nialame-results.sarif"
sarif_path.write_text(json.dumps(sarif_report, indent=2), encoding="utf-8")

print(f"Findings: {total_findings} — fichiers concernés: {len(results)}")
print(f"SARIF écrit dans {sarif_path}")

github_output = sys.stdin.isatty() is False  # toujours vrai en CI
import os
output_file = os.environ.get("GITHUB_OUTPUT")
if output_file:
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"sarif-path={sarif_path}\n")
        f.write(f"findings-count={total_findings}\n")

if worst_severity >= fail_threshold and fail_on != "none":
    print(f"::error::Nialame a détecté des findings de sévérité >= {fail_on}.")
    sys.exit(1)

sys.exit(0)
PYEOF
