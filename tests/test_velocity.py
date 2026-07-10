"""F9 velocity detection: settings, classifier, tracker unit tests."""

from __future__ import annotations

import threading

import pytest

import terminus.config.settings as settings_mod
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import SchemaWhitelist
from terminus.signature.facts import RoleResolver, to_signature_facts
from terminus.velocity.classifier import extraction_class
from terminus.velocity.tracker import VelocityTracker, get_velocity_trackers


def test_velocity_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    settings_mod._settings = None
    s = settings_mod.get_settings()
    assert s.velocity_enabled is False
    assert s.velocity_enforce_enabled is False
    assert s.velocity_window_seconds == 60
    assert s.velocity_threshold == 30
    assert s.velocity_max_tracked == 10000
    settings_mod._settings = None


def test_velocity_settings_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "5")
    settings_mod._settings = None
    s = settings_mod.get_settings()
    assert s.velocity_enabled is True
    assert s.velocity_threshold == 5
    settings_mod._settings = None


def _facts(sql: str):
    parsed = parse_sql(sql, collect_signature_facts=True)
    resolver = RoleResolver(SchemaWhitelist(tables=["public.users", "public.orders"]))
    return to_signature_facts(parsed, resolver)


def test_select_with_where_is_counted() -> None:
    facts = _facts("SELECT id FROM public.users WHERE id = 1")
    assert extraction_class(facts, "fp123") == "fp123"


def test_select_without_where_is_not_counted() -> None:
    facts = _facts("SELECT id FROM public.users")
    assert extraction_class(facts, "fp123") is None


def test_insert_is_not_counted() -> None:
    facts = _facts("INSERT INTO public.users (id) VALUES (1)")
    assert extraction_class(facts, "fp123") is None


def test_aggregate_probe_with_where_is_counted() -> None:
    facts = _facts("SELECT count(*) FROM public.users WHERE id < 500")
    assert extraction_class(facts, "fpAgg") == "fpAgg"


def test_class_key_is_the_passed_fingerprint_only() -> None:
    # Name-free guarantee: the key is exactly the fingerprint, never a table/column.
    facts = _facts("SELECT id FROM public.users WHERE id = 1")
    assert extraction_class(facts, "opaque-hash") == "opaque-hash"


def test_tracker_trips_only_above_threshold() -> None:
    tracker = VelocityTracker(window_seconds=60, threshold=2, max_tracked=100, clock=lambda: 0.0)
    assert tracker.record_and_check("a", "k") is False  # count 1
    assert tracker.record_and_check("a", "k") is False  # count 2
    assert tracker.record_and_check("a", "k") is True  # count 3 > 2


def test_tracker_window_resets_after_expiry() -> None:
    now = [0.0]
    tracker = VelocityTracker(window_seconds=60, threshold=2, max_tracked=100, clock=lambda: now[0])
    assert tracker.record_and_check("a", "k") is False
    assert tracker.record_and_check("a", "k") is False
    assert tracker.record_and_check("a", "k") is True
    now[0] = 61.0  # advance past the window
    assert tracker.record_and_check("a", "k") is False  # fresh window, count 1


def test_tracker_buckets_are_independent_per_agent_and_class() -> None:
    tracker = VelocityTracker(window_seconds=60, threshold=1, max_tracked=100, clock=lambda: 0.0)
    assert tracker.record_and_check("a", "k1") is False
    assert tracker.record_and_check("b", "k1") is False  # different agent, own bucket
    assert tracker.record_and_check("a", "k2") is False  # different class, own bucket
    assert tracker.record_and_check("a", "k1") is True  # a/k1 now count 2 > 1


def test_tracker_lru_eviction_bounds_memory() -> None:
    tracker = VelocityTracker(window_seconds=60, threshold=100, max_tracked=2, clock=lambda: 0.0)
    tracker.record_and_check("a", "k1")
    tracker.record_and_check("a", "k2")
    tracker.record_and_check("a", "k3")  # evicts the LRU entry ("a","k1")
    assert len(tracker._state) == 2
    # k1 was evicted, so touching it again starts a fresh count of 1, not a resumed 2.
    assert tracker.record_and_check("a", "k1") is False
    assert len(tracker._state) == 2


def test_tracker_is_thread_safe() -> None:
    tracker = VelocityTracker(
        window_seconds=1000, threshold=10**9, max_tracked=100, clock=lambda: 0.0
    )

    def worker() -> None:
        for _ in range(1000):
            tracker.record_and_check("a", "k")

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert tracker._state[("a", "k")][1] == 4000  # no lost updates


def test_get_velocity_trackers_is_singleton(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    settings_mod._settings = None
    get_velocity_trackers.cache_clear()
    trackers = get_velocity_trackers()
    assert trackers is get_velocity_trackers()
    assert trackers.auth is not trackers.unauth  # independent pools
    get_velocity_trackers.cache_clear()


def test_tracker_window_boundary_is_inclusive() -> None:
    # The reset uses a strict `>` (now - window_start > window_seconds), so the
    # instant EXACTLY at window_seconds stays in the current window; only strictly
    # past it resets.
    now = [0.0]
    tracker = VelocityTracker(
        window_seconds=60, threshold=100, max_tracked=100, clock=lambda: now[0]
    )
    tracker.record_and_check("a", "k")  # count 1 at t=0
    now[0] = 60.0  # exactly at the boundary: 60 - 0 == 60, NOT > 60
    tracker.record_and_check("a", "k")  # same window, count 2
    assert tracker._state[("a", "k")] == (0.0, 2)
    now[0] = 60.001  # strictly past the boundary
    tracker.record_and_check("a", "k")  # resets to a fresh window, count 1
    assert tracker._state[("a", "k")][1] == 1


def test_record_velocity_anomaly_increments() -> None:
    from terminus.observability.metrics import VELOCITY_ANOMALIES, record_velocity_anomaly

    before = VELOCITY_ANOMALIES.labels(enforced="false")._value.get()
    record_velocity_anomaly(enforced=False)
    after = VELOCITY_ANOMALIES.labels(enforced="false")._value.get()
    assert after == before + 1
