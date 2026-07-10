from __future__ import annotations

import json

import pytest

from terminus.audit.audit_logger import AUDIT_SCHEMA_VERSION, AuditLogger, configure_logging
from terminus.mcp.audit import record_tool_decision
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import get_policy_engine


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    configure_logging()
    yield
    settings_mod._settings = None


def _emit(capsys, *, tool: str, approval_status: str | None) -> dict:
    parsed = parse_sql("SELECT id FROM public.users WHERE id = 1")
    decision = get_policy_engine().evaluate(parsed, agent_id="analytics_agent_42")
    record_tool_decision(
        audit_logger=AuditLogger(),
        request_id="r1",
        sql="SELECT id FROM public.users WHERE id = 1",
        agent_id="analytics_agent_42",
        parsed_sql=parsed,
        decision=decision,
        tool=tool,
        approval_status=approval_status,
    )
    out = capsys.readouterr().out
    events = [
        json.loads(line)
        for line in out.strip().splitlines()
        if "terminus_intercept_decision" in line
    ]
    assert events, out
    return events[-1]


def test_record_tool_decision_signs_tool_value(capsys):
    event = _emit(capsys, tool="query", approval_status=None)
    assert event["event_signature"]
    assert event["schema_version"] == AUDIT_SCHEMA_VERSION
    assert event["mcp_tool"] == "query"  # the VALUE, not just the key name
    assert event["mcp_approval_status"] is None
    # MCP context no longer rides metadata; metadata_keys returns to generic use.
    assert event["metadata_keys"] == []


def test_record_tool_decision_signs_approval_outcome(capsys):
    event = _emit(capsys, tool="execute", approval_status="approved")
    assert event["mcp_tool"] == "execute"
    assert event["mcp_approval_status"] == "approved"
