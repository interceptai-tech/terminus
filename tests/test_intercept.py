"""Integration-style tests for the Terminus intercept endpoint."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from fastapi.testclient import TestClient as _TC

from terminus.auth.dependency import authenticate
from terminus.auth.tokens import mint_token
from terminus.interceptor.router import agent_identifier, enforce_rate_limit
from terminus.main import app

_SECRET = "test-jwt-secret-at-least-32-bytes-long-xxxxx"


def _probe_client() -> _TC:
    app = FastAPI()

    @app.post("/_probe", dependencies=[Depends(authenticate)])
    async def _probe(request: Request) -> dict[str, str | None]:
        return {"trusted": getattr(request.state, "trusted_agent_id", None)}

    return _TC(app)


def test_authenticate_valid_token_sets_trusted_id(monkeypatch, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    reset_auth_caches()
    token = mint_token("analytics_agent_42", _SECRET, expires_in=timedelta(hours=1))
    resp = _probe_client().post("/_probe", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["trusted"] == "analytics_agent_42"


def test_authenticate_bad_token_401(monkeypatch, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    reset_auth_caches()
    resp = _probe_client().post("/_probe", headers={"Authorization": "Bearer not.a.jwt"})
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


def test_authenticate_unknown_sub_401(monkeypatch, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    reset_auth_caches()
    token = mint_token("ghost_agent", _SECRET, expires_in=timedelta(hours=1))
    resp = _probe_client().post("/_probe", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_authenticate_no_token_permissive_is_legacy(monkeypatch, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_REQUIRE_AUTH", "false")
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    reset_auth_caches()
    resp = _probe_client().post("/_probe")
    assert resp.status_code == 200
    assert resp.json()["trusted"] is None


def test_authenticate_no_token_require_auth_401(monkeypatch, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_REQUIRE_AUTH", "true")
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    reset_auth_caches()
    resp = _probe_client().post("/_probe")
    assert resp.status_code == 401


def test_authenticate_non_bearer_scheme_is_legacy(monkeypatch, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_REQUIRE_AUTH", "false")
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    reset_auth_caches()
    resp = _probe_client().post("/_probe", headers={"Authorization": "Basic abc123"})
    assert resp.status_code == 200
    assert resp.json()["trusted"] is None


@pytest.fixture
def client() -> TestClient:
    """Test client for the FastAPI app."""
    return TestClient(app)


def _fake_request(
    *,
    headers: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
    host: str = "1.2.3.4",
    trusted: str | None = None,
) -> SimpleNamespace:
    """Minimal stand-in for a Starlette Request for identifier/limiter tests."""
    return SimpleNamespace(
        headers=headers or {},
        query_params=query or {},
        client=SimpleNamespace(host=host),
        scope={"path": "/intercept"},
        state=SimpleNamespace(trusted_agent_id=trusted),
    )


async def test_agent_identifier_prefers_agent_header() -> None:
    """Per-agent rate limiting keys on X-Agent-ID, falling back to client host."""
    by_header = await agent_identifier(_fake_request(headers={"X-Agent-ID": "agent_7"}))
    by_query = await agent_identifier(_fake_request(query={"agent_id": "agent_9"}))
    by_host = await agent_identifier(_fake_request(host="10.0.0.5"))

    assert by_header.startswith("agent_7:")
    assert by_query.startswith("agent_9:")
    assert by_host.startswith("10.0.0.5:")


async def test_rate_limit_fails_open_when_limiter_uninitialized() -> None:
    """With Redis/limiter not initialized (as in tests) the guard must no-op."""
    result = await enforce_rate_limit(_fake_request(), SimpleNamespace(headers={}))

    assert result is None


def test_health_check_returns_ok(client: TestClient) -> None:
    """Health endpoint must return 200 with status ok."""
    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "terminus"


def test_intercept_allows_approved_select(client: TestClient) -> None:
    """Approved SELECT query should be allowed per policy.yaml."""
    payload = {
        "sql": "SELECT id, name FROM public.users WHERE id = 1",
        "agent_id": "analytics_agent_42",
    }

    response = client.post("/intercept", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["operation"] == "SELECT"
    assert "public.users" in data["tables"]
    assert data["policy_id"] == "allow_analytics_reads"


def test_intercept_denies_drop_table(client: TestClient) -> None:
    """DROP TABLE must be denied with high risk score."""
    payload = {
        "sql": "DROP TABLE public.users",
        "agent_id": "analytics_agent_42",
    }

    response = client.post("/intercept", json=payload)

    assert response.status_code == 403
    data = response.json()
    assert data["decision"] == "deny"
    assert data["operation"] == "DROP"
    assert data["risk_score"] == 1.0
    assert "remediation" in data


def test_intercept_denied_response_includes_remediation_header(client: TestClient) -> None:
    """Deny responses must include X-Terminus-Remediation header."""
    payload = {
        "sql": "DROP TABLE public.secret_table",
        "agent_id": "analytics_agent_42",
    }

    response = client.post("/intercept", json=payload)

    assert response.status_code == 403
    assert "X-Terminus-Remediation" in response.headers
    assert len(response.headers["X-Terminus-Remediation"]) > 10
    # The header uses the policy remediation message, which is more specific
    assert any(
        word in response.headers["X-Terminus-Remediation"].lower()
        for word in ["destructive", "blocked", "approval"]
    )


def test_intercept_denies_non_whitelisted_table(client: TestClient) -> None:
    """A query against a table outside the schema whitelist is blocked with feedback."""
    response = client.post(
        "/intercept",
        json={"sql": "SELECT * FROM hr.salaries", "agent_id": "analytics_agent_42"},
    )

    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "deny"
    assert "whitelist" in body["reason"].lower()


def test_metrics_endpoint_exposes_prometheus(client: TestClient) -> None:
    """The /metrics endpoint must be mounted and return Prometheus text format."""
    response = client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    # Metric families defined in observability/metrics.py should be present.
    assert "terminus_requests_total" in response.text
    assert "terminus_parser_latency_seconds" in response.text


def test_intercept_increments_request_counter(client: TestClient) -> None:
    """An allowed intercept must increment terminus_requests_total with its labels."""
    client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users", "agent_id": "analytics_agent_42"},
    )

    metrics = client.get("/metrics").text

    # A labelled sample for the allow decision on a SELECT must now exist.
    assert 'terminus_requests_total{action="allow"' in metrics
    assert 'operation="SELECT"' in metrics


def test_intercept_counts_smuggling_attempt(client: TestClient) -> None:
    """A query with a smuggling pattern must bump the smuggling counter."""
    client.post(
        "/intercept",
        json={
            "sql": "SELECT * FROM public.users UNION SELECT password FROM public.secrets",
            "agent_id": "analytics_agent_42",
        },
    )

    metrics = client.get("/metrics").text

    assert "terminus_smuggling_attempts_total" in metrics


def test_intercept_response_includes_risk_reasons(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={"sql": "DROP TABLE public.users", "agent_id": "analytics_agent_42"},
    )
    assert response.status_code == 403
    body = response.json()
    assert "risk_reasons" in body
    assert "destructive_operation" in body["risk_reasons"]


def test_intercept_denies_disallowed_column(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={"sql": "SELECT password_hash FROM public.users", "agent_id": "analytics_agent_42"},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["decision"] == "deny"
    assert body["policy_id"] == "column_whitelist"
    assert "password_hash" in body["reason"]


def test_intercept_denies_select_star_on_restricted_table(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={"sql": "SELECT * FROM public.users", "agent_id": "analytics_agent_42"},
    )
    assert response.status_code == 403
    assert "wildcard_select" in response.json()["risk_reasons"]


def test_intercept_allows_select_star_on_unrestricted_table(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={"sql": "SELECT * FROM public.orders", "agent_id": "analytics_agent_42"},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"


def test_intercept_allows_listed_columns(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={
            "sql": "SELECT id, name FROM public.users WHERE id = 1",
            "agent_id": "analytics_agent_42",
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"


def test_intercept_attaches_suggested_sql_for_wildcard(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={"sql": "SELECT * FROM public.users", "agent_id": "analytics_agent_42"},
    )
    assert response.status_code == 403
    remediation = response.json()["remediation"]
    assert remediation["suggested_sql"] == "SELECT email, id, name FROM public.users"
    # the rewrite must never ride in the header
    assert "SELECT" not in response.headers["X-Terminus-Remediation"]


def test_intercept_no_suggested_sql_for_destructive(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={"sql": "DROP TABLE public.users", "agent_id": "analytics_agent_42"},
    )
    assert response.status_code == 403
    assert response.json()["remediation"]["suggested_sql"] is None


def test_intercept_allowed_query_has_no_remediation(client: TestClient) -> None:
    response = client.post(
        "/intercept",
        json={
            "sql": "SELECT id, name FROM public.users WHERE id = 1",
            "agent_id": "analytics_agent_42",
        },
    )
    assert response.status_code == 200
    assert response.json()["remediation"] is None


# ---------------------------------------------------------------------------
# Task 4: trusted identity tests
# ---------------------------------------------------------------------------


async def test_agent_identifier_uses_trusted_id_over_header() -> None:
    # When authenticated, the rate-limit key is the trusted id, NOT the header.
    req = _fake_request(headers={"X-Agent-ID": "attacker"}, trusted="analytics_agent_42")
    key = await agent_identifier(req)
    assert key.startswith("analytics_agent_42:")


def _auth_client(monkeypatch, reset_auth_caches, *, require_auth: bool = False) -> TestClient:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    monkeypatch.setenv("TERMINUS_REQUIRE_AUTH", "true" if require_auth else "false")
    reset_auth_caches()
    return TestClient(app)


def test_intercept_token_identity_overrides_body_agent_id(monkeypatch, reset_auth_caches) -> None:
    # Absolute anti-spoofing: a valid token's sub wins over a conflicting body agent_id.
    client = _auth_client(monkeypatch, reset_auth_caches)
    token = mint_token("analytics_agent_42", _SECRET, expires_in=timedelta(hours=1))
    resp = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users WHERE id = 1", "agent_id": "attacker"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert (
        body["policy_id"] == "allow_analytics_reads"
    )  # matched as analytics_agent_42, not attacker


def test_intercept_bad_token_401_even_permissive(monkeypatch, reset_auth_caches) -> None:
    client = _auth_client(monkeypatch, reset_auth_caches)  # require_auth=false
    resp = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users", "agent_id": "x"},
        headers={"Authorization": "Bearer garbage"},
    )
    assert resp.status_code == 401


def test_intercept_no_token_require_auth_401(monkeypatch, reset_auth_caches) -> None:
    client = _auth_client(monkeypatch, reset_auth_caches, require_auth=True)
    resp = client.post("/intercept", json={"sql": "SELECT id FROM public.users", "agent_id": "x"})
    assert resp.status_code == 401


def test_intercept_no_token_permissive_legacy_still_works(monkeypatch, reset_auth_caches) -> None:
    client = _auth_client(monkeypatch, reset_auth_caches)  # require_auth=false
    resp = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users WHERE id = 1", "agent_id": "analytics_agent_42"},
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"
