"""Bind MCP tool context into the existing tamper-evident audit chain.

Reuses AuditLogger.log_decision (the signed, chained decision record). As of audit
schema v2, mcp_tool and mcp_approval_status are first-class SIGNED fields: the chain
records which tool ran and the approval outcome, tamper-evidently. metadata is no
longer used for MCP context.
"""

from __future__ import annotations

from terminus.audit.audit_logger import AuditLogger
from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import PolicyDecision


def record_tool_decision(
    *,
    audit_logger: AuditLogger,
    request_id: str,
    sql: str,
    agent_id: str | None,
    parsed_sql: ParsedSQL,
    decision: PolicyDecision,
    tool: str,
    approval_status: str | None,
    enforcement_mode: str = "enforce",
    would_deny: bool = False,
    would_deny_reason_code: str | None = None,
) -> None:
    """Write one MCP tool call into the audit chain.

    enforcement_mode/would_deny/would_deny_reason_code are the same graduated-
    autonomy v3 evidence the HTTP router logs (see terminus.policy.graduated):
    defaults match the pre-Task-6 (enforce-only) behavior so any caller that does
    not pass them is unaffected.
    """
    audit_logger.log_decision(
        request_id=request_id,
        sql=sql,
        agent_id=agent_id,
        parsed_sql=parsed_sql,
        decision=decision,
        remediation_present=decision.action != "allow",
        mcp_tool=tool,
        mcp_approval_status=approval_status,
        agent_authenticated=agent_id is not None,
        enforcement_mode=enforcement_mode,
        would_deny=would_deny,
        would_deny_reason_code=would_deny_reason_code,
    )
