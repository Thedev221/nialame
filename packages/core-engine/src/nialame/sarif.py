"""Génération de rapports SARIF 2.1.0 à partir des findings Nialame."""
from __future__ import annotations

from typing import Any

from nialame.models import FileReviewResult, Severity

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def build_sarif_report(
    results: list[FileReviewResult], tool_name: str = "nialame-ai", tool_version: str = "0.1.0"
) -> dict[str, Any]:
    rules_index: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for file_result in results:
        for finding in file_result.findings:
            if finding.rule_id not in rules_index:
                rules_index[finding.rule_id] = {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.message},
                    "properties": {"cwe": finding.cwe} if finding.cwe else {},
                }

            sarif_results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
                    "message": {"text": finding.explanation},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_result.file_path},
                                "region": {
                                    "startLine": finding.location.start_line,
                                    "startColumn": finding.location.start_column + 1,
                                    "endLine": finding.location.end_line,
                                    "endColumn": finding.location.end_column + 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "confidence": finding.confidence.value,
                        "tier": finding.tier,
                    },
                }
            )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/nialame/nialame-ai",
                        "rules": list(rules_index.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
