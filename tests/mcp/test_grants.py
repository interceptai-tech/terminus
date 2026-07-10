from __future__ import annotations

import dataclasses

import pytest

from terminus.mcp.grants import Allowed, Denied, ExecutionGrant, NeedsApproval
from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import PolicyDecision


def _parsed(operation: str = "SELECT") -> ParsedSQL:
    return ParsedSQL(operation=operation, risk_score=0.0)


def _decision(action: str = "allow", reason_code: str = "test") -> PolicyDecision:
    return PolicyDecision(action=action, reason="ok", reason_code=reason_code)


def test_execution_grant_is_frozen():
    grant = ExecutionGrant(statement="SELECT 1", agent_id="a1", request_id="r1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        grant.statement = "DROP TABLE users"  # type: ignore[misc]


def test_outcome_types_carry_expected_fields():
    grant = ExecutionGrant(statement="SELECT 1", agent_id="a1", request_id="r1")
    parsed = _parsed()
    allow_decision = _decision("allow")

    allowed = Allowed(grant=grant, parsed=parsed, decision=allow_decision)
    assert allowed.grant is grant
    assert allowed.parsed is parsed
    assert allowed.decision is allow_decision

    needs_approval = NeedsApproval(
        grant=grant,
        request_id="r1",
        reason="high risk",
        parsed=parsed,
        decision=allow_decision,
    )
    assert needs_approval.grant is grant
    assert needs_approval.parsed is parsed
    assert needs_approval.decision is allow_decision

    deny_decision = _decision("deny", "schema_whitelist")
    denied = Denied(
        reason="nope",
        reason_code="schema_whitelist",
        remediation=None,
        parsed=parsed,
        decision=deny_decision,
    )
    assert denied.reason_code == "schema_whitelist"
    assert denied.parsed is parsed
    assert denied.decision is deny_decision


def test_outcome_dataclasses_are_frozen():
    grant = ExecutionGrant(statement="SELECT 1", agent_id="a1", request_id="r1")
    parsed = _parsed()
    decision = _decision()
    allowed = Allowed(grant=grant, parsed=parsed, decision=decision)
    with pytest.raises(dataclasses.FrozenInstanceError):
        allowed.decision = decision  # type: ignore[misc]
