"""F9 velocity detection: end-to-end interceptor integration."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import terminus.config.settings as settings_mod
from terminus.auth.tokens import mint_token
from terminus.main import app
from terminus.velocity.tracker import VelocityTracker, get_velocity_trackers

_SECRET = "test-jwt-secret-at-least-32-bytes-long-xxxxx"

_ALLOWED = "SELECT id FROM public.orders WHERE id = 1"  # SELECT+WHERE, whitelisted, allowed
# examples/policy.yaml's "allow_analytics_reads" rule (the only rule that allows
# a plain SELECT on public.orders) additionally requires agent_id to match
# "analytics_agent_*" or "reporting_cron"; anything else falls through to
# default_action: deny. Use agent ids under that glob so _ALLOWED actually
# resolves to "allow" and the tests isolate the velocity effect instead of
# confounding it with an unrelated default-deny.


def _reset() -> None:
    settings_mod._settings = None
    get_velocity_trackers.cache_clear()


def _post(client: TestClient, sql: str, agent_id: str) -> dict:
    return client.post(
        "/intercept", json={"sql": sql, "agent_id": agent_id, "request_id": "r"}
    ).json()


def test_velocity_observe_flags_after_threshold_without_blocking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    _reset()
    client = TestClient(app)
    r1 = _post(client, _ALLOWED, "analytics_agent_velo_observe")
    _post(client, _ALLOWED, "analytics_agent_velo_observe")
    r3 = _post(client, _ALLOWED, "analytics_agent_velo_observe")  # count 3 > 2 -> anomaly
    assert r1["decision"] == "allow"
    assert "velocity_anomaly" not in r1["risk_reasons"]
    assert r3["decision"] == "allow"  # observe: never blocks
    assert "velocity_anomaly" in r3["risk_reasons"]
    _reset()


def test_velocity_enforce_blocks_after_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    # Enforce only ever denies an AUTHENTICATED (JWT-verified) agent identity;
    # a self-asserted agent_id can no longer drive a deny (Finding 1), so this
    # test mints a real token for a registered agent to still exercise the
    # enforce-deny path end to end.
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    _reset()
    client = TestClient(app)
    token = mint_token("analytics_agent_42", _SECRET, expires_in=timedelta(hours=1))
    headers = {"Authorization": f"Bearer {token}"}
    r1 = client.post(
        "/intercept",
        json={"sql": _ALLOWED, "request_id": "r"},
        headers=headers,
    )
    client.post(
        "/intercept",
        json={"sql": _ALLOWED, "request_id": "r"},
        headers=headers,
    )
    r3 = client.post(
        "/intercept",
        json={"sql": _ALLOWED, "request_id": "r"},
        headers=headers,
    )
    assert r1.json()["decision"] == "allow"
    assert r3.status_code == 403
    assert r3.json()["decision"] == "deny"
    assert "velocity" in r3.json()["reason"].lower()
    assert "velocity_anomaly" in r3.json()["risk_reasons"]
    _reset()


def test_velocity_enforce_is_observe_only_for_unauthenticated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Finding 1: enforce must require an authenticated identity. A self-asserted
    # (unauthenticated) agent_id is spoofable, so even past threshold it must
    # stay observe-only (flagged, never denied) -- otherwise an attacker could
    # spoof a victim's agent_id (or flood the shared "unknown" bucket) to get
    # the victim's legitimate queries denied.
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    _reset()
    client = TestClient(app)
    r1 = _post(client, _ALLOWED, "analytics_agent_velo_unauth")
    _post(client, _ALLOWED, "analytics_agent_velo_unauth")
    r3 = _post(client, _ALLOWED, "analytics_agent_velo_unauth")  # count 3 > 2, but unauthenticated
    assert r1["decision"] == "allow"
    assert r3["decision"] == "allow"  # unauthenticated: observe only, never denied
    assert "velocity_anomaly" in r3["risk_reasons"]  # observe still fires
    _reset()


def test_velocity_enforce_does_not_override_an_existing_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    _reset()
    client = TestClient(app)
    # `ssn` is not allowlisted on public.users -> a column_whitelist deny, independent of F9.
    denied = "SELECT ssn FROM public.users WHERE id = 1"
    r1 = client.post("/intercept", json={"sql": denied, "agent_id": "velo-deny", "request_id": "r"})
    first_reason = r1.json()["reason"]
    client.post("/intercept", json={"sql": denied, "agent_id": "velo-deny", "request_id": "r"})
    r3 = client.post("/intercept", json={"sql": denied, "agent_id": "velo-deny", "request_id": "r"})
    assert r1.json()["decision"] == "deny"
    assert r3.json()["decision"] == "deny"
    assert r3.json()["reason"] == first_reason  # velocity did NOT rewrite the deny
    assert "velocity" not in r3.json()["reason"].lower()
    _reset()


def test_velocity_disabled_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    _reset()  # velocity_enabled defaults False
    client = TestClient(app)
    last = {}
    for _ in range(5):
        last = _post(client, _ALLOWED, "analytics_agent_velo_off")
    assert last["decision"] == "allow"
    assert "velocity_anomaly" not in last["risk_reasons"]
    _reset()


def test_velocity_failure_is_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "1")
    _reset()

    def _boom(self: VelocityTracker, agent_id: str, class_key: str) -> bool:
        raise RuntimeError("tracker down")

    monkeypatch.setattr(VelocityTracker, "record_and_check", _boom)
    client = TestClient(app)
    r = client.post(
        "/intercept",
        json={"sql": _ALLOWED, "agent_id": "analytics_agent_velo_fail", "request_id": "r"},
    )
    assert r.status_code == 200  # no 500
    assert r.json()["decision"] == "allow"  # fail-open: no block despite enforce
    assert "velocity_anomaly" not in r.json()["risk_reasons"]
    _reset()


def test_velocity_unauthenticated_cannot_poison_authenticated_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A spoofed unauthenticated agent_id must NOT feed the authenticated victim's
    # enforcement counter: trust-namespaced keys keep them in separate buckets.
    from datetime import timedelta

    from terminus.auth.tokens import mint_token

    secret = "z" * 40
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_JWT_SECRET", secret)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    _reset()
    client = TestClient(app)
    # Attacker: 3 unauthenticated requests spoofing the victim's registered subject.
    for _ in range(3):
        r = client.post(
            "/intercept",
            json={"sql": _ALLOWED, "agent_id": "analytics_agent_42", "request_id": "r"},
        )
        assert r.status_code == 200  # unauthenticated: observe-only, never denied
    # Victim: a genuine JWT-authenticated request must still be allowed (own bucket).
    token = mint_token("analytics_agent_42", secret, expires_in=timedelta(hours=1))
    victim = client.post(
        "/intercept",
        json={"sql": _ALLOWED, "agent_id": "analytics_agent_42", "request_id": "r"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert victim.status_code == 200
    assert victim.json()["decision"] == "allow"
    _reset()


def test_velocity_unauth_flood_cannot_evict_authenticated_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An unauth flood (many unique self-asserted ids) must not evict the victim's
    # authenticated enforcement counter: separate bounded pools keep auth safe.
    from datetime import timedelta

    from terminus.auth.tokens import mint_token

    secret = "z" * 40
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_JWT_SECRET", secret)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    monkeypatch.setenv("TERMINUS_VELOCITY_MAX_TRACKED", "3")  # tiny cap to force eviction
    _reset()
    client = TestClient(app)
    token = mint_token("analytics_agent_42", secret, expires_in=timedelta(hours=1))
    hdr = {"Authorization": f"Bearer {token}"}
    body = {"sql": _ALLOWED, "agent_id": "analytics_agent_42", "request_id": "r"}
    assert client.post("/intercept", json=body, headers=hdr).json()["decision"] == "allow"
    assert client.post("/intercept", json=body, headers=hdr).json()["decision"] == "allow"
    for i in range(6):  # flood unauth pool with unique ids, well over max_tracked
        # Must match the "analytics_agent_*" glob so _ALLOWED actually resolves to
        # allow (see module docstring); otherwise the flood gets an unrelated
        # policy-level 403 and this test stops isolating the velocity effect.
        assert (
            client.post(
                "/intercept",
                json={"sql": _ALLOWED, "agent_id": f"analytics_agent_spoof{i}", "request_id": "r"},
            ).status_code
            == 200
        )
    victim = client.post("/intercept", json=body, headers=hdr)
    assert victim.status_code == 403  # auth bucket survived the flood -> still enforced
    assert victim.json()["decision"] == "deny"
    _reset()


def test_velocity_metric_label_reflects_actual_enforcement_not_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An observe-only anomaly on UNAUTHENTICATED traffic under enforce POSTURE must be
    # counted as enforced=false (the request was not denied), not enforced=true.
    from terminus.observability.metrics import VELOCITY_ANOMALIES

    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    _reset()
    client = TestClient(app)
    before_true = VELOCITY_ANOMALIES.labels(enforced="true")._value.get()
    before_false = VELOCITY_ANOMALIES.labels(enforced="false")._value.get()
    last = None
    for _ in range(3):
        last = client.post(
            "/intercept",
            json={"sql": _ALLOWED, "agent_id": "analytics_agent_metric", "request_id": "r"},
        )
    assert last.json()["decision"] == "allow"  # unauthenticated -> observe only, not denied
    assert VELOCITY_ANOMALIES.labels(enforced="true")._value.get() == before_true  # not inflated
    assert VELOCITY_ANOMALIES.labels(enforced="false")._value.get() == before_false + 1
    _reset()
