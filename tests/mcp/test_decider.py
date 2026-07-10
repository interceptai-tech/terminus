from __future__ import annotations

import pytest

from terminus.config.settings import get_settings
from terminus.mcp.decider import decide
from terminus.mcp.grants import Allowed, Denied, NeedsApproval
from terminus.policy.policy_engine import get_policy_engine


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    yield
    settings_mod._settings = None


async def _decide(sql, expected):
    return await decide(
        sql=sql,
        agent_id="analytics_agent_42",
        request_id="r1",
        expected=expected,
        policy_engine=get_policy_engine(),
        settings=get_settings(),
    )


async def test_allowed_read_returns_grant():
    outcome = await _decide("SELECT id FROM public.users WHERE id = 1", "read")
    assert isinstance(outcome, Allowed)
    assert outcome.grant.statement == "SELECT id FROM public.users WHERE id = 1"
    # The outcome must carry the ACTUAL parse/decision, not a placeholder that
    # audit would have to re-derive later.
    assert outcome.parsed.operation == "SELECT"
    assert outcome.decision.action == "allow"


async def test_write_via_query_tool_is_denied_wrong_tool():
    outcome = await _decide("UPDATE public.users SET name = 'x' WHERE id = 1", "read")
    assert isinstance(outcome, Denied)
    assert outcome.reason_code == "wrong_tool"
    # The wrong-tool short-circuit fires BEFORE policy evaluation, so the carried
    # decision must be a synthetic deny (not an allow the engine never returned).
    assert outcome.decision.action == "deny"
    assert outcome.decision.reason_code == "wrong_tool"
    assert outcome.parsed.operation == "UPDATE"


async def test_select_via_execute_tool_is_denied_wrong_tool():
    outcome = await _decide("SELECT id FROM public.users WHERE id = 1", "write")
    assert isinstance(outcome, Denied)
    assert outcome.reason_code == "wrong_tool"
    assert outcome.decision.action == "deny"
    assert outcome.decision.reason_code == "wrong_tool"
    assert outcome.parsed.operation == "SELECT"


async def test_policy_denied_write_returns_denied_with_remediation():
    outcome = await _decide("DELETE FROM public.users WHERE id = 1", "write")
    assert isinstance(outcome, Denied)
    assert outcome.remediation is not None
    assert outcome.decision.action == "deny"
    assert outcome.parsed.operation == "DELETE"


async def test_allowed_low_risk_write_returns_grant():
    outcome = await _decide("UPDATE public.users SET name = 'x' WHERE id = 1", "write")
    assert isinstance(outcome, Allowed)
    assert outcome.decision.action == "allow"
    assert outcome.parsed.operation == "UPDATE"


async def test_allowed_high_risk_write_needs_approval(monkeypatch):
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_RISK_THRESHOLD", "0.4")
    settings_mod._settings = None
    outcome = await _decide("UPDATE public.users SET name = 'x' WHERE id = 1", "write")
    assert isinstance(outcome, NeedsApproval)
    assert outcome.grant.statement.startswith("UPDATE")
    assert outcome.decision.action == "allow"
    assert outcome.parsed.operation == "UPDATE"


async def test_invalid_sql_is_denied_fail_closed():
    outcome = await _decide("NOT SQL AT ALL ;;;", "read")
    assert isinstance(outcome, Denied)


async def test_invalid_sql_gets_engine_reason_code_not_wrong_tool():
    # An unparseable statement must reach the engine and be denied with its
    # accurate, stable reason_code (invalid_sql), not mislabelled "wrong_tool".
    outcome = await _decide("NOT SQL AT ALL ;;;", "read")
    assert isinstance(outcome, Denied)
    assert outcome.reason_code == "invalid_sql"


async def test_multi_statement_gets_engine_reason_code_not_wrong_tool():
    # Multi-statement SQL is blocked by the engine with its own reason_code;
    # the wrong-tool shortcut must not swallow it.
    outcome = await _decide("SELECT 1; SELECT 2", "read")
    assert isinstance(outcome, Denied)
    assert outcome.reason_code == "multi_statement"


async def test_wildcard_deny_carries_suggested_rewrite():
    outcome = await _decide("SELECT * FROM public.users", "read")
    assert isinstance(outcome, Denied)
    assert outcome.remediation is not None
    suggested = outcome.remediation.suggested_sql
    assert suggested is not None
    for col in ("id", "name", "email"):
        assert col in suggested
    assert "*" not in suggested


async def test_destructive_deny_has_no_rewrite():
    outcome = await _decide("DELETE FROM public.users WHERE id = 1", "write")
    assert isinstance(outcome, Denied)
    assert outcome.remediation is not None
    assert outcome.remediation.suggested_sql is None
