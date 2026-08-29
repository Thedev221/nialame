from nialame.models import Confidence, FileReviewResult, Finding, Range, Severity
from nialame.sarif import build_sarif_report


def test_sarif_report_structure():
    finding = Finding(
        rule_id="NIA-SQLI-001",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        message="SQL injection",
        explanation="Requête non paramétrée.",
        proof="query = f'SELECT * FROM t WHERE id={x}'",
        location=Range(start_line=2, start_column=4, end_line=2, end_column=40),
        enclosing_symbol="get_item",
        tier="tier1_deterministic",
    )
    result = FileReviewResult(file_path="app.py", findings=[finding])
    report = build_sarif_report([result])

    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    assert run["tool"]["driver"]["name"] == "nialame-ai"
    assert run["results"][0]["ruleId"] == "NIA-SQLI-001"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
