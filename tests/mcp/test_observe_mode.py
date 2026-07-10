"""Graduated autonomy on the MCP path: observe softening, floor invariants, and the
grant no-bypass guarantee (structural test in test_no_bypass.py, exercised here too).

Mirrors tests/mcp/test_server.py's fixtures/patterns (FakePool, _dev_env, the 1s
approval-timeout trick) but drives ToolService for an observe-mode agent
(onboarding_agent_9, examples/agents.yaml) vs. an enforce-mode one
(analytics_agent_42, no trust_level field).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from terminus.audit.audit_logger import AuditLogger, configure_logging
from terminus.config.settings import get_settings
from terminus.mcp.approvals import ApprovalBroker
from terminus.mcp.executor import Executor
from terminus.mcp.server import ToolService
from terminus.observability.metrics import WOULD_DENY_TOTAL
from terminus.policy.policy_engine import get_policy_engine


class FakePool:
    def __init__(self) -> None:
        self.executed: list[str] = []

    async def fetch(self, sql: str) -> list[dict[str, Any]]:
        return [{"id": 1}]

    async def execute(self, sql: str) -> str:
        self.executed.append(sql)
        return "UPDATE 1"


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    configure_logging()
    yield
    settings_mod._settings = None


def _service(pool: FakePool, agent_id: str) -> ToolService:
    return ToolService(
        settings=get_settings(),
        policy_engine=get_policy_engine(),
        executor=Executor(pool),
        broker=ApprovalBroker(),
        audit_logger=AuditLogger(),
        agent_id=agent_id,
    )


def _decision_events(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    out = capsys.readouterr().out
    return [json.loads(line) for line in out.splitlines() if "terminus_intercept_decision" in line]


async def test_observe_softened_read_executes(monkeypatch, reset_auth_caches, capsys):
    # onboarding_agent_9 is registry trust: observe. A schema_whitelist deny
    # (public.secrets is not whitelisted) must soften to an allow and actually
    # execute, with the audit chain recording both the truthful allow AND the
    # would-deny evidence.
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    reset_auth_caches()
    pool = FakePool()

    result = await _service(pool, "onboarding_agent_9").query("SELECT id FROM public.secrets")

    assert result["status"] == "ok"
    assert result["rows"] == [{"id": 1}]

    events = _decision_events(capsys)
    assert len(events) == 1
    event = events[0]
    assert event["decision"] == "allow"
    assert event["reason_code"] == "observe_softened"
    assert event["would_deny"] is True
    assert event["would_deny_reason_code"] == "schema_whitelist"
    assert event["enforcement_mode"] == "observe"


async def test_observe_floor_denies_no_grant(monkeypatch, reset_auth_caches):
    # Floor reason codes (invalid_sql, multi_statement, ...) are never softenable,
    # even for an observe-mode agent: no benign reading, no grant, pool untouched.
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    reset_auth_caches()
    pool = FakePool()
    svc = _service(pool, "onboarding_agent_9")

    result = await svc.execute("NOT SQL AT ALL ;;;")
    assert result["status"] == "denied"

    result = await svc.query("SELECT 1; SELECT 2")
    assert result["status"] == "denied"

    assert pool.executed == []


async def test_softened_high_risk_write_needs_approval(monkeypatch, reset_auth_caches):
    # A softened policy_rule deny on a high-risk write must still route to human
    # approval: observe never bypasses break-glass. With no approver and a 1s
    # timeout it ends up pending/expired, but the grant is never auto-executed.
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_RISK_THRESHOLD", "0.4")
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_TIMEOUT_SECONDS", "1")
    reset_auth_caches()
    pool = FakePool()

    result = await _service(pool, "onboarding_agent_9").execute(
        "DELETE FROM public.users WHERE id = 1"
    )

    assert result["status"] in {"pending_approval", "approval_expired"}
    assert pool.executed == []


async def test_enforce_agent_unchanged(monkeypatch, reset_auth_caches):
    # analytics_agent_42 has no trust_level field (registry default: enforce), so
    # graduated autonomy being on elsewhere must not change its outcome at all.
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    reset_auth_caches()
    pool = FakePool()

    result = await _service(pool, "analytics_agent_42").execute(
        "DELETE FROM public.users WHERE id = 1"
    )

    assert result["status"] == "denied"
    assert pool.executed == []


async def test_would_deny_metric_increments_on_mcp_path(monkeypatch, reset_auth_caches):
    # F-final #1: the HTTP router increments terminus_would_deny_total in
    # interceptor/router.py, but the MCP surface only threaded would_deny into
    # the audit event, never the metric. An MCP-only deployment's
    # promotion-evidence dashboard (terminus_would_deny_total{reason_code,
    # operation}) must read nonzero for the same softened-query evidence the
    # HTTP path already records (see test_would_deny_metric_increments in
    # tests/test_observe_http.py, mirrored here for the MCP surface).
    monkeypatch.setenv("TERMINUS_GRADUATED_AUTONOMY_ENABLED", "true")
    reset_auth_caches()
    pool = FakePool()

    before = WOULD_DENY_TOTAL.labels(
        reason_code="schema_whitelist", operation="SELECT"
    )._value.get()

    result = await _service(pool, "onboarding_agent_9").query("SELECT id FROM public.secrets")

    assert result["status"] == "ok"
    after = WOULD_DENY_TOTAL.labels(reason_code="schema_whitelist", operation="SELECT")._value.get()
    assert after == before + 1


async def test_switch_off_observe_agent_enforced(reset_auth_caches):
    # With the flag unset (default False), even a registry observe agent is
    # resolved to enforce: the same deny as today.
    reset_auth_caches()
    pool = FakePool()

    result = await _service(pool, "onboarding_agent_9").execute(
        "DELETE FROM public.users WHERE id = 1"
    )

    assert result["status"] == "denied"
    assert pool.executed == []
