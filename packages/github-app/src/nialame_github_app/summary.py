"""Construction du résumé Markdown publié dans le check run GitHub."""
from __future__ import annotations

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def build_summary_markdown(results: list[dict]) -> tuple[str, str, str]:
    """Retourne (conclusion, title, summary_markdown).

    ``results`` est une liste de dicts {"file_path": str, "findings": [Finding-like dict]}.
    """
    total = sum(len(r["findings"]) for r in results)

    if total == 0:
        return (
            "success",
            "Nialame — aucun problème détecté",
            "Aucun finding de sécurité détecté par l'analyse déterministe (Tier 1).",
        )

    worst_severity = max(
        (f["severity"] for r in results for f in r["findings"]),
        key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[s],
    )
    conclusion = "failure" if worst_severity in {"critical", "high"} else "neutral"

    lines = [f"**{total} finding(s) détecté(s) dans {len(results)} fichier(s).**", ""]
    for r in results:
        lines.append(f"### `{r['file_path']}`")
        for f in r["findings"]:
            emoji = _SEVERITY_EMOJI.get(f["severity"], "⚪")
            lines.append(f"- {emoji} `{f['rule_id']}` (ligne {f['location']['start_line']}) — {f['message']}")
        lines.append("")
    lines.append("_Analyse déterministe uniquement (Tier 1, AST). Revue humaine requise avant toute correction._")

    return conclusion, f"Nialame — {total} finding(s) détecté(s)", "\n".join(lines)
