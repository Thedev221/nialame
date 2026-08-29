import hashlib
import hmac

import pytest

from nialame_github_app.webhook_signature import InvalidWebhookSignatureError, verify_signature

SECRET = "test-secret"


def _sign(body: bytes, secret: str = SECRET) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_accepts_valid_signature():
    body = b'{"action": "opened"}'
    signature = _sign(body)
    verify_signature(body, signature, SECRET)  # ne doit pas lever


def test_rejects_missing_signature():
    with pytest.raises(InvalidWebhookSignatureError):
        verify_signature(b"{}", None, SECRET)


def test_rejects_invalid_signature():
    body = b'{"action": "opened"}'
    with pytest.raises(InvalidWebhookSignatureError):
        verify_signature(body, "sha256=deadbeef", SECRET)


def test_rejects_signature_for_wrong_secret():
    body = b'{"action": "opened"}'
    signature = _sign(body, secret="other-secret")
    with pytest.raises(InvalidWebhookSignatureError):
        verify_signature(body, signature, SECRET)


def test_rejects_malformed_signature_header():
    with pytest.raises(InvalidWebhookSignatureError):
        verify_signature(b"{}", "not-a-valid-header", SECRET)
