import time

from nialame_github_app.dedup import DeliveryDeduplicator


def test_first_delivery_is_not_duplicate():
    dedup = DeliveryDeduplicator(ttl_seconds=60)
    assert dedup.is_duplicate("delivery-1") is False


def test_replayed_delivery_is_duplicate():
    dedup = DeliveryDeduplicator(ttl_seconds=60)
    dedup.is_duplicate("delivery-1")
    assert dedup.is_duplicate("delivery-1") is True


def test_expired_delivery_is_not_duplicate(monkeypatch):
    dedup = DeliveryDeduplicator(ttl_seconds=0)
    dedup.is_duplicate("delivery-1")
    time.sleep(0.01)
    assert dedup.is_duplicate("delivery-1") is False
