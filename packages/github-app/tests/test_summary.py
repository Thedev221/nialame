from nialame_github_app.summary import build_summary_markdown


def test_no_findings_produces_success():
    conclusion, title, summary = build_summary_markdown([])
    assert conclusion == "success"
    assert "aucun" in summary.lower()


def test_critical_finding_produces_failure():
    results = [
        {
            "file_path": "app.py",
            "findings": [
                {
                    "rule_id": "NIA-SQLI-001",
                    "severity": "critical",
                    "message": "SQL injection",
                    "location": {"start_line": 4},
                }
            ],
        }
    ]
    conclusion, title, summary = build_summary_markdown(results)
    assert conclusion == "failure"
    assert "NIA-SQLI-001" in summary


def test_low_severity_produces_neutral():
    results = [
        {
            "file_path": "app.py",
            "findings": [
                {
                    "rule_id": "NIA-LOW-001",
                    "severity": "low",
                    "message": "Style issue",
                    "location": {"start_line": 1},
                }
            ],
        }
    ]
    conclusion, _, _ = build_summary_markdown(results)
    assert conclusion == "neutral"
