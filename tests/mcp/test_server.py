from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from terminus.audit.audit_logger import AuditLogger, configure_logging
from terminus.config.settings import get_settings
from terminus.mcp.approvals import ApprovalBroker
from terminus.mcp.executor import Executor
from terminus.mcp.server import ToolService
from terminus.observability.metrics import HOLDS_ACTIVE
from terminus.policy.policy_engine import get_policy_engine


class FakePool:
    def __init__(self):
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


def _service(pool):
    return ToolService(
        settings=get_settings(),
        policy_engine=get_policy_engine(),
        executor=Executor(pool),
        broker=ApprovalBroker(),
        audit_logger=AuditLogger(),
        agent_id="analytics_agent_42",
    )


async def test_query_allowed_returns_rows():
    pool = FakePool()
    result = await _service(pool).query("SELECT id FROM public.users WHERE id = 1")
    assert result["status"] == "ok"
    assert result["rows"] == [{"id": 1}]


async def test_query_denied_returns_remediation_and_does_not_execute():
    pool = FakePool()
    result = await _service(pool).query("SELECT * FROM public.secrets")
    assert result["status"] == "denied"
    assert "remediation" in result
    assert pool.executed == []


async def test_execute_denied_write_does_not_mutate():
    pool = FakePool()
    result = await _service(pool).execute("DELETE FROM public.users WHERE id = 1")
    assert result["status"] == "denied"
    assert pool.executed == []


async def test_execute_high_risk_write_pends_without_executing(monkeypatch):
    import terminus.config.settings as settings_mod

    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_RISK_THRESHOLD", "0.4")
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_TIMEOUT_SECONDS", "1")
    settings_mod._settings = None
    pool = FakePool()
    result = await _service(pool).execute("UPDATE public.users SET name = 'x' WHERE id = 1")
    assert result["status"] in {"pending_approval", "approval_expired"}
    # With no approver and a 1s timeout, the write must never execute.
    assert pool.executed == []
    settings_mod._settings = None


class ExplodingPool:
    """A pool whose driver errors embed the failing SQL, like asyncpg often does."""

    def __init__(self):
        self.executed: list[str] = []

    async def fetch(self, sql: str) -> list[dict[str, Any]]:
        raise RuntimeError(f"syntax error in {sql}")

    async def execute(self, sql: str) -> str:
        raise RuntimeError(f"syntax error in {sql}")


async def test_query_db_error_never_leaks_sql_to_client():
    sql = "SELECT id FROM public.users WHERE id = 1"
    result = await _service(ExplodingPool()).query(sql)
    assert result["status"] == "error"
    assert result["reason_code"] == "execution_error"
    serialized = json.dumps(result)
    # No fragment of the statement (or the driver's message) may reach the client.
    assert sql not in serialized
    assert "public.users" not in serialized
    assert "syntax error" not in serialized


async def test_execute_db_error_never_leaks_sql_to_client():
    sql = "UPDATE public.users SET name = 'x' WHERE id = 1"
    result = await _service(ExplodingPool()).execute(sql)
    assert result["status"] == "error"
    assert result["reason_code"] == "execution_error"
    serialized = json.dumps(result)
    assert sql not in serialized
    assert "public.users" not in serialized
    assert "syntax error" not in serialized


async def test_wrong_tool_denial_audits_deny_not_allow(capsys):
    # Regression: a SELECT sent to `execute` must be denied (wrong_tool) to the
    # client AND the signed audit chain must record that same deny, never an
    # `allow` from a stale re-evaluation of a different (or no-op) statement.
    pool = FakePool()
    sql = "SELECT id FROM public.users WHERE id = 1"
    result = await _service(pool).execute(sql)
    assert result["status"] == "denied"
    assert result["reason_code"] == "wrong_tool"
    assert pool.executed == []

    out = capsys.readouterr().out
    events = [
        json.loads(line) for line in out.splitlines() if "terminus_intercept_decision" in line
    ]
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert events[0]["reason_code"] == "wrong_tool"


async def test_max_holds_gate_denies_and_audits_and_updates_gauge(monkeypatch, capsys):
    # settings.mcp_approval_max_holds == 1: a first high-risk write fills the
    # single available slot and stays pending; a second, concurrent high-risk
    # write must be denied by the gate BEFORE it ever reaches broker.submit,
    # audited "denied", and never bump broker.pending() past 1. HOLDS_ACTIVE
    # must read len(broker.pending()) both right after submit and again after
    # broker.wait() resolves (real broker size, not a locally tracked counter).
    import terminus.config.settings as settings_mod

    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_RISK_THRESHOLD", "0.4")
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_MAX_HOLDS", "1")
    settings_mod._settings = None

    pool = FakePool()
    broker = ApprovalBroker()
    svc = ToolService(
        settings=get_settings(),
        policy_engine=get_policy_engine(),
        executor=Executor(pool),
        broker=broker,
        audit_logger=AuditLogger(),
        agent_id="analytics_agent_42",
    )
    sql = "UPDATE public.users SET name = 'x' WHERE id = 1"

    first_task = asyncio.create_task(svc.execute(sql))
    loop = asyncio.get_event_loop()
    deadline = loop.time() + 2.0
    while not broker.pending():
        if loop.time() > deadline:
            raise AssertionError("first execute() never reached broker.submit()")
        await asyncio.sleep(0.01)

    # Gauge reflects the broker's real pending set right after submit.
    assert HOLDS_ACTIVE._value.get() == 1 == len(broker.pending())

    result = await svc.execute(sql)
    assert result["status"] == "denied"
    assert result["reason_code"] == "max_holds_exceeded"
    assert len(broker.pending()) == 1  # the gate never submitted a second hold

    out = capsys.readouterr().out
    events = [
        json.loads(line) for line in out.splitlines() if "terminus_intercept_decision" in line
    ]
    gated_events = [e for e in events if e["request_id"] == result["request_id"]]
    assert len(gated_events) == 1
    assert gated_events[0]["mcp_approval_status"] == "denied"

    # Resolve the first hold; the gauge must fall back to the broker's real
    # (now empty) size after broker.wait() returns.
    first_rid = broker.pending()[0]
    assert broker.approve(first_rid) is True
    first_result = await first_task
    assert first_result["status"] == "ok"
    assert HOLDS_ACTIVE._value.get() == 0 == len(broker.pending())

    settings_mod._settings = None


async def test_audit_failure_fails_closed_before_execution(monkeypatch):
    # If the audit chain cannot record the decision, the statement must NOT run.
    import terminus.mcp.server as server_mod

    def _boom(**kwargs: Any) -> None:
        raise RuntimeError("audit backend down")

    monkeypatch.setattr(server_mod, "record_tool_decision", _boom)
    pool = FakePool()
    result = await _service(pool).execute("UPDATE public.users SET name = 'x' WHERE id = 1")
    assert result["status"] == "error"
    assert result["reason_code"] == "audit_error"
    assert pool.executed == []
