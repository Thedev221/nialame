from nialame.redaction import redact_for_llm, redact_secrets_regex


def test_redacts_aws_key():
    source = "AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'\n"
    redacted, types = redact_secrets_regex(source)
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted
    assert "aws_access_key" in types


def test_redacts_secret_variable_assignment():
    source = "password = 'hunter2super'\nprint(password)\n"
    result = redact_for_llm(source)
    assert "hunter2super" not in result.redacted_source
    assert "secret_variable_assignment" in result.redaction_types


def test_no_redaction_on_clean_code():
    source = "def add(a, b):\n    return a + b\n"
    result = redact_for_llm(source)
    assert result.redacted_source == source
    assert result.redaction_types == []
