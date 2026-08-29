"""Vérification cryptographique des webhooks GitHub.

Toute requête webhook dont la signature est absente ou invalide est
rejetée. Comparaison en temps constant pour éviter les attaques par
timing.
"""
from __future__ import annotations

import hashlib
import hmac


class InvalidWebhookSignatureError(Exception):
    pass


def verify_signature(payload_body: bytes, signature_header: str | None, secret: str) -> None:
    """Lève InvalidWebhookSignatureError si la signature est absente ou invalide.

    ``signature_header`` est la valeur brute de l'en-tête
    ``X-Hub-Signature-256``, au format ``sha256=<hex>``.
    """
    if not signature_header:
        raise InvalidWebhookSignatureError("En-tête X-Hub-Signature-256 absent.")

    if not signature_header.startswith("sha256="):
        raise InvalidWebhookSignatureError("Format de signature inattendu.")

    expected = hmac.new(secret.encode("utf-8"), payload_body, hashlib.sha256).hexdigest()
    provided = signature_header.removeprefix("sha256=")

    if not hmac.compare_digest(expected, provided):
        raise InvalidWebhookSignatureError("Signature HMAC invalide.")
