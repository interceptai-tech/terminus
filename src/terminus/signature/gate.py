"""Cheap, config-driven decision: should this query produce a signature?"""

from __future__ import annotations

from terminus.config.settings import TerminusSettings
from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import PolicyDecision


def should_emit_signature(
    decision: PolicyDecision, parsed_sql: ParsedSQL, settings: TerminusSettings
) -> bool:
    """Emit denies, smuggling/hidden-subquery queries, and high-risk allows.

    Short-circuits to False when disabled so the common allow path does almost
    nothing. The risk comparison is >= against signature_risk_threshold (0.5).
    """
    if not settings.signatures_enabled:
        return False
    if decision.action == "deny":
        return True
    if parsed_sql.security_flags.has_smuggling_pattern:
        return True
    if parsed_sql.security_flags.has_hidden_subquery:
        return True
    return parsed_sql.risk_score >= settings.signature_risk_threshold
