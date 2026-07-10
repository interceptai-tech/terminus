"""The decider: parse, evaluate, classify, and mint an ExecutionGrant on an allow.

This is the ONLY module that constructs an ExecutionGrant. It runs the existing
decision engine unchanged and never touches a database.
"""

from __future__ import annotations

import asyncio
from typing import Literal

from terminus.config.settings import TerminusSettings
from terminus.mcp.grants import Allowed, DecisionOutcome, Denied, ExecutionGrant, NeedsApproval
from terminus.parser.sql_parser import parse_sql
from terminus.policy.graduated import soften_if_observing
from terminus.policy.policy_engine import PolicyDecision, PolicyEngine
from terminus.remediation.remediation import build_remediation

_WRITE_OPERATIONS = {"INSERT", "UPDATE", "DELETE", "MERGE"}


async def decide(
    *,
    sql: str,
    agent_id: str | None,
    request_id: str,
    expected: Literal["read", "write"],
    policy_engine: PolicyEngine,
    settings: TerminusSettings,
    trust_level: Literal["observe", "enforce"] = "enforce",
) -> DecisionOutcome:
    """Return an Allowed / Denied / NeedsApproval outcome for one tool call.

    Fail-closed: any parse/engine error yields Denied. A grant is minted only when
    the engine allows the statement (and, for a high-risk write, only after approval).

    Ordering: for valid single statements the wrong-tool check fires before policy
    evaluation; invalid or multi-statement SQL skips it so the engine can deny with
    its accurate reason_code (invalid_sql / oversize_sql / multi_statement). The
    wrong-tool short-circuit is floor by construction (fires before evaluate, so it
    never sees trust_level and can never be softened).

    trust_level is resolved by the caller (terminus.policy.graduated) from the
    boot-validated MCP agent identity, never from anything caller-supplied.
    soften_if_observing runs immediately after evaluate(), same as the HTTP router:
    it may only convert a deny into an allow-with-evidence for an observe agent on
    the OBSERVE_SOFTENABLE allowlist, and every downstream check (grant minting,
    high-risk-write approval) then sees the effective (possibly softened) decision.
    """
    parsed = await asyncio.to_thread(
        parse_sql,
        sql,
        dialect=settings.sql_dialect or None,
        normalize_dialect=settings.sql_dialect,
        max_length=settings.max_sql_length,
    )

    # The wrong-tool check applies only to valid single statements. Parse failures
    # (operation == "INVALID") and multi-statement strings must fall through to the
    # engine, which denies them with the accurate, stable reason_code
    # (invalid_sql / oversize_sql / multi_statement) and real remediation, instead
    # of the misleading "wrong_tool" label. Fail-closed either way.
    if parsed.is_valid and parsed.operation != "MULTI_STATEMENT":
        is_read = parsed.operation == "SELECT"
        if expected == "read" and not is_read:
            reason = "This tool runs read-only SELECT statements; use the execute tool."
            return Denied(
                reason=reason,
                reason_code="wrong_tool",
                remediation=None,
                parsed=parsed,
                decision=_wrong_tool_decision(reason),
            )
        if expected == "write" and is_read:
            reason = "This tool runs writes; use the query tool for SELECT."
            return Denied(
                reason=reason,
                reason_code="wrong_tool",
                remediation=None,
                parsed=parsed,
                decision=_wrong_tool_decision(reason),
            )

    decision = policy_engine.evaluate(parsed, agent_id=agent_id)
    decision, would_deny, would_deny_reason_code = soften_if_observing(decision, trust_level)
    if decision.action != "allow":
        # Same off-loop re-parse rule and the same F10c trust boundary as the HTTP
        # router: the rewrite re-parses and re-normalizes the raw SQL, so the fold
        # must use ONLY the trusted deployment dialect, never anything caller-supplied.
        suggested_sql: str | None = await asyncio.to_thread(
            policy_engine.suggest_rewrite,
            parsed,
            sql,
            decision,
            agent_id=agent_id,
            dialect=settings.sql_dialect,
            max_length=settings.max_sql_length,
        )
        remediation = build_remediation(decision, parsed, suggested_sql=suggested_sql)
        return Denied(
            reason=decision.reason,
            reason_code=decision.reason_code,
            remediation=remediation,
            parsed=parsed,
            decision=decision,
        )

    grant = ExecutionGrant(statement=sql, agent_id=agent_id, request_id=request_id)

    if (
        parsed.operation in _WRITE_OPERATIONS
        and parsed.risk_score >= settings.mcp_approval_risk_threshold
    ):
        return NeedsApproval(
            grant=grant,
            request_id=request_id,
            reason=(
                f"This {parsed.operation} is high-risk (risk {parsed.risk_score:.2f} "
                f">= {settings.mcp_approval_risk_threshold:.2f}) and requires human approval."
            ),
            parsed=parsed,
            decision=decision,
            would_deny=would_deny,
            would_deny_reason_code=would_deny_reason_code,
        )

    return Allowed(
        grant=grant,
        parsed=parsed,
        decision=decision,
        would_deny=would_deny,
        would_deny_reason_code=would_deny_reason_code,
    )


def _wrong_tool_decision(reason: str) -> PolicyDecision:
    """Synthesize a deny decision for the wrong-tool short-circuit.

    This fires BEFORE policy_engine.evaluate() runs, so there is no real engine
    decision yet; audit must still record something truthful, so this mirrors
    exactly what the engine would report for a request it never saw: a deny with
    a stable reason_code, no policy match, no remediation hint.
    """
    return PolicyDecision(
        action="deny",
        policy_id=None,
        policy_name=None,
        reason=reason,
        reason_code="wrong_tool",
        remediation_message=None,
        column_violation=None,
    )
