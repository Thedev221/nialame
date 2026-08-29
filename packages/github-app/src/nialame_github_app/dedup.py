"""Déduplication des webhooks GitHub par delivery id, avec TTL en mémoire.

Protection anti-replay : un même ``delivery_id`` reçu deux fois dans la
fenêtre TTL est ignoré silencieusement (mais journalisé).
"""
from __future__ import annotations

import time


class DeliveryDeduplicator:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}

    def _evict_expired(self, now: float) -> None:
        expired = [k for k, ts in self._seen.items() if now - ts > self._ttl_seconds]
        for k in expired:
            del self._seen[k]

    def is_duplicate(self, delivery_id: str) -> bool:
        now = time.monotonic()
        self._evict_expired(now)
        if delivery_id in self._seen:
            return True
        self._seen[delivery_id] = now
        return False

    def size(self) -> int:
        return len(self._seen)
