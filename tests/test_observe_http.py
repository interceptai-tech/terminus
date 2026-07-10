"""Graduated autonomy on the HTTP path: observe softening + would-deny evidence.

Mirrors the F9 velocity integration tests for the authenticated-request pattern
(mint a real JWT for a registered agent id rather than trusting the self-asserted
`agent_id` field) and asserts against both the HTTP response and the emitted
audit JSON line (captured via capsys, since AuditLogger prints structlog JSON to
stdout once `configure_logging()` has run).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from terminus.audit.audit_logger import configure_logging
from terminus.auth.tokens import mint_token
from terminus.main import app
from terminus.observability.metrics import WOULD_DENY_TOTAL
from terminus.velocity.tracker import get_velocity_trackers

_SECRET = "test-jwt-secret-at-least-32-bytes-long-xxxxx"


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force structlog into JSON-to-stdout mode regardless of what earlier tests
    # in the session left global structlog config as (process-global state).
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    configure_logging()


def _reset(reset_auth_caches) -> None:
    """Clear settings + governance manager (fixture) and the velocity cache."""
    reset_auth_caches()
    get_velocity_trackers.cache_clear()


def _auth_headers(agent_id: str) -> dict[str, str]:
    token = mint_token(agent_id, _SECRET, expires_in=timedelta(hours=1))
    return {"Authorization": f"Bearer {token}"}


def _decision_lines(capsys: pytest.CaptureFixture[str]) -> list[dict]:
    """Parse every emitted audit line and keep the intercept-decision events."""
    lines = [ln for ln in capsys.readouterr().out.strip().splitlines() if ln]
    events = [json.loads(ln) for ln in lines]
    return [e for e in events if e.get("event") == "terminus_intercept_decision"]


def test_switch_off_is_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """TERMINUS_GRADUATED_AUTONOMY_ENABLED unset (default False): today's
    always-enforce behavior is unchanged even for a registered observe agent."""
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    _reset(reset_auth_caches)
    client = TestClient(app)

    resp = client.post(
        "/intercept",
        json={"sql": "DELETE FROM public.users WHERE id = 1", "request_id": "r"},
        headers=_auth_headers("onboarding_agent_9"),
    )

    assert resp.status_code == 403
    assert resp.json()["decision"] == "deny"
    event = _decision_lines(capsys)[-1]
    assert event["enforcement_mode"] == "enforce"
    assert event["would_deny"] is False


def test_observe_softens_each_softenable_code(
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each softenable deny code, for a registered observe agent, becomes an
    allow with the original deny preserved as evidence (audit + risk_reasons)."""
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    _reset(reset_auth_caches)
    client = TestClient(app)
    headers = _auth_headers("onboarding_agent_9")

    cases = [
        ("DELETE FROM public.users WHERE id = 1", "policy_rule"),
        ("SELECT id FROM public.secrets", "schema_whitelist"),
        ("SELECT ssn FROM public.users", "column_whitelist"),
    ]
    for sql, original_code in cases:
        resp = client.post("/intercept", json={"sql": sql, "request_id": "r"}, headers=headers)
        body = resp.json()
        assert resp.status_code == 200, body
        assert body["decision"] == "allow"
        assert f"would_deny:{original_code}" in body["risk_reasons"]

        event = _decision_lines(capsys)[-1]
        assert event["decision"] == "allow"
        assert event["reason_code"] == "observe_softened"
        assert event["would_deny"] is True
        assert event["would_deny_reason_code"] == original_code
        assert event["enforcement_mode"] == "observe"


def test_observe_softens_risk_threshold_and_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The remaining two softenable codes: risk_threshold and default.

    risk_threshold needs an agent matching the example policy's
    rate_limit_experimental_agents rule (agent_ids research_*/experimental_agent_*,
    max_destructive_risk_score 0.2), so a temp registry adds a research_* agent at
    observe trust; an UPDATE with WHERE scores 0.45 > 0.2 and denies with
    risk_threshold. default uses onboarding_agent_9, whose id matches no allow
    rule for a plain whitelisted SELECT, falling through to default-deny.
    """
    agents_path = tmp_path / "agents.yaml"
    agents_path.write_text(
        """version: "1.0"
agents:
  - id: onboarding_agent_9
    trust_level: observe
  - id: research_observer_1
    trust_level: observe
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", str(agents_path))
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    _reset(reset_auth_caches)
    client = TestClient(app)

    cases = [
        # research_* matches the rate_limit_experimental_agents rule whose
        # max_destructive_risk_score (0.2) is below UPDATE-with-WHERE's 0.45.
        (
            "research_observer_1",
            "UPDATE public.users SET name = 'x' WHERE id = 1",
            "risk_threshold",
        ),
        # onboarding_agent_9 matches no allow rule for this SELECT (the
        # allow_analytics_reads rule requires analytics_agent_*/reporting_cron),
        # so the engine falls through to default-deny.
        ("onboarding_agent_9", "SELECT id FROM public.orders WHERE id = 1", "default"),
    ]
    for agent_id, sql, original_code in cases:
        resp = client.post(
            "/intercept",
            json={"sql": sql, "request_id": "r"},
            headers=_auth_headers(agent_id),
        )
        body = resp.json()
        assert resp.status_code == 200, (original_code, body)
        assert body["decision"] == "allow"
        assert f"would_deny:{original_code}" in body["risk_reasons"]

        event = _decision_lines(capsys)[-1]
        assert event["reason_code"] == "observe_softened"
        assert event["would_deny"] is True
        assert event["would_deny_reason_code"] == original_code
        assert event["enforcement_mode"] == "observe"


def test_softened_would_deny_emits_signature(
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A softened would-deny must still emit a terminus_signature line.

    Softening turns the deny into an allow before the signature gate runs, so
    the gate's emit-on-deny branch never fires and a typical softened violation
    (risk 0.05 SELECT) would emit nothing; the router must emit on would_deny so
    the signature record seeds the store as promotion evidence.
    """
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    _reset(reset_auth_caches)
    client = TestClient(app)

    resp = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.secrets", "request_id": "r"},
        headers=_auth_headers("onboarding_agent_9"),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"  # softened schema_whitelist deny

    lines = [ln for ln in capsys.readouterr().out.strip().splitlines() if ln]
    signature_events = [
        e for e in (json.loads(ln) for ln in lines) if e.get("event") == "terminus_signature"
    ]
    assert signature_events, "softened would-deny emitted no signature line"
    assert signature_events[-1]["reason_code"] == "observe_softened"


def test_would_deny_signature_respects_signatures_master_switch(
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """TERMINUS_SIGNATURES_ENABLED=false means ZERO signature telemetry, even for
    a softened would-deny: the would-deny evidence emission must not bypass the
    signatures master switch (and with collectors off, an emission would carry
    coarsened facts that pollute shape-grouping). Decision, audit evidence, and
    the would-deny metric are unchanged by the switch."""
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_SIGNATURES_ENABLED", "false")
    _reset(reset_auth_caches)
    client = TestClient(app)

    before = WOULD_DENY_TOTAL.labels(
        reason_code="schema_whitelist", operation="SELECT"
    )._value.get()
    resp = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.secrets", "request_id": "r"},
        headers=_auth_headers("onboarding_agent_9"),
    )

    # Softening itself is unaffected by the signatures switch.
    body = resp.json()
    assert resp.status_code == 200
    assert body["decision"] == "allow"
    assert "would_deny:schema_whitelist" in body["risk_reasons"]
    after = WOULD_DENY_TOTAL.labels(reason_code="schema_whitelist", operation="SELECT")._value.get()
    assert after == before + 1

    lines = [ln for ln in capsys.readouterr().out.strip().splitlines() if ln]
    events = [json.loads(ln) for ln in lines]
    # Audit evidence still present...
    decision_events = [e for e in events if e.get("event") == "terminus_intercept_decision"]
    assert decision_events[-1]["would_deny"] is True
    assert decision_events[-1]["would_deny_reason_code"] == "schema_whitelist"
    # ...but no signature telemetry of any kind.
    signature_events = [e for e in events if e.get("event") == "terminus_signature"]
    assert not signature_events, "signatures master switch off must mean zero signature telemetry"


def test_floor_stays_denied_in_observe(
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Deny codes NOT on OBSERVE_SOFTENABLE are floor: denied even in observe."""
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    _reset(reset_auth_caches)
    client = TestClient(app)
    headers = _auth_headers("onboarding_agent_9")

    floor_sqls = [
        "SELECT FROM WHERE )(",  # invalid_sql
        "SELECT 1; SELECT 2",  # multi_statement
        "SELECT pg_sleep(9) FROM public.users",  # injection_function
        # nested_write: a DELETE smuggled inside a writable CTE under a
        # top-level SELECT (same construction as the parser's own fixtures).
        "WITH d AS (DELETE FROM public.users WHERE id = 1 RETURNING id) SELECT 1",
    ]
    for sql in floor_sqls:
        resp = client.post("/intercept", json={"sql": sql, "request_id": "r"}, headers=headers)
        assert resp.status_code == 403, (sql, resp.json())
        assert resp.json()["decision"] == "deny"
        event = _decision_lines(capsys)[-1]
        assert event["would_deny"] is False, sql

    # Verify the injection_function deny is real AST-based enforcement against
    # the actual denied function, not a coincidental default-deny: the parser
    # must have flagged pg_sleep specifically (INJECTION_FUNCTION_NAMES).
    injection_resp = client.post(
        "/intercept",
        json={"sql": "SELECT pg_sleep(9) FROM public.users", "request_id": "r"},
        headers=headers,
    )
    assert injection_resp.json()["reason"]  # sanity: a real deny reason present
    injection_event = _decision_lines(capsys)[-1]
    assert "pg_sleep" in injection_event["security_flags"]["suspicious_keywords"]


def test_self_asserted_observe_id_is_enforced(
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A self-asserted (unauthenticated) agent_id can never select observe mode,
    even if it names a registered observe agent: identity must be JWT-verified."""
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    _reset(reset_auth_caches)
    client = TestClient(app)

    resp = client.post(
        "/intercept",
        json={
            "sql": "DELETE FROM public.users WHERE id = 1",
            "agent_id": "onboarding_agent_9",
            "request_id": "r",
        },
    )

    assert resp.status_code == 403
    assert resp.json()["decision"] == "deny"
    event = _decision_lines(capsys)[-1]
    assert event["enforcement_mode"] == "enforce"
    assert event["would_deny"] is False


def test_velocity_enforce_gated_by_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
) -> None:
    """F9 velocity enforcement only escalates allow->deny for an enforce-trust
    agent; an observe-trust agent tripping the same threshold stays allowed."""
    agents_path = tmp_path / "agents.yaml"
    agents_path.write_text(
        """version: "1.0"
agents:
  - id: analytics_agent_observe
    trust_level: observe
  - id: analytics_agent_enforce
    trust_level: enforce
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", str(agents_path))
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_VELOCITY_THRESHOLD", "2")
    _reset(reset_auth_caches)
    client = TestClient(app)

    # examples/policy.yaml's allow_analytics_reads rule matches any
    # "analytics_agent_*" id, so this is a genuine (non-softened) allow for
    # both agents below; only trust decides whether velocity may escalate it.
    allowed_sql = "SELECT id FROM public.orders WHERE id = 1"

    observe_headers = _auth_headers("analytics_agent_observe")
    for _ in range(2):
        client.post(
            "/intercept", json={"sql": allowed_sql, "request_id": "r"}, headers=observe_headers
        )
    r_observe = client.post(
        "/intercept", json={"sql": allowed_sql, "request_id": "r"}, headers=observe_headers
    )
    assert r_observe.status_code == 200
    assert r_observe.json()["decision"] == "allow"  # anomaly recorded, never enforced

    enforce_headers = _auth_headers("analytics_agent_enforce")
    for _ in range(2):
        client.post(
            "/intercept", json={"sql": allowed_sql, "request_id": "r"}, headers=enforce_headers
        )
    r_enforce = client.post(
        "/intercept", json={"sql": allowed_sql, "request_id": "r"}, headers=enforce_headers
    )
    assert r_enforce.status_code == 403
    assert r_enforce.json()["decision"] == "deny"


def test_would_deny_metric_increments(
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
) -> None:
    """terminus_would_deny_total increments for the softened reason_code+operation."""
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    _reset(reset_auth_caches)
    client = TestClient(app)

    before = WOULD_DENY_TOTAL.labels(reason_code="policy_rule", operation="DELETE")._value.get()
    resp = client.post(
        "/intercept",
        json={"sql": "DELETE FROM public.users WHERE id = 1", "request_id": "r"},
        headers=_auth_headers("onboarding_agent_9"),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"
    after = WOULD_DENY_TOTAL.labels(reason_code="policy_rule", operation="DELETE")._value.get()

    assert after == before + 1
