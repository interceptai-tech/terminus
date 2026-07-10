"""Graduated autonomy: the per-agent observe softening transform.

The policy engine stays trust-unaware and fail-closed; this transform runs AFTER
evaluate() on both surfaces (HTTP router, MCP decider) and may only convert a deny
into an allow-with-evidence for an observe-mode agent, and only for reason codes on
the OBSERVE_SOFTENABLE allowlist. Everything not on the list, including any future
deny code, is floor: denied even in observe (no benign reading, per the F11
precedent). Softening keys on unspoofable identity only (JWT-verified on HTTP,
boot-validated on MCP); a self-asserted agent_id can never select the weaker
posture (the F9 lesson, inverted).
"""

from __future__ import annotations

from typing import Literal

from terminus.auth.registry import AgentRegistry
from terminus.config.settings import TerminusSettings
from terminus.policy.policy_engine import PolicyDecision

# ALLOWLIST of softenable deny codes. Floor by construction: invalid_sql,
# oversize_sql, multi_statement, injection_function, nested_write, wrong_tool,
# and anything added in the future until it is deliberately listed here.
OBSERVE_SOFTENABLE: frozenset[str] = frozenset(
    {"schema_whitelist", "column_whitelist", "policy_rule", "risk_threshold", "default"}
)

WOULD_DENY_REASON_CODE = "observe_softened"


def resolve_enforcement_mode(
    *,
    settings: TerminusSettings,
    registry: AgentRegistry,
    agent_id: str | None,
    agent_authenticated: bool,
) -> Literal["observe", "enforce"]:
    """Effective mode for this request. Enforce unless every gate passes."""
    if not settings.graduated_autonomy_enabled:
        return "enforce"
    if not agent_authenticated or agent_id is None:
        return "enforce"
    return registry.trust_of(agent_id)


def soften_if_observing(
    decision: PolicyDecision, mode: str
) -> tuple[PolicyDecision, bool, str | None]:
    """Return (effective_decision, would_deny, original_reason_code).

    Only an observe-mode deny with a softenable reason_code is converted; the
    effective decision is a truthful allow (the statement will execute) labeled
    observe_softened, with the original deny preserved for audit and metrics.
    """
    if mode != "observe" or decision.action == "allow":
        return decision, False, None
    if decision.reason_code not in OBSERVE_SOFTENABLE:
        return decision, False, None
    softened = PolicyDecision(
        action="allow",
        policy_id=decision.policy_id,
        policy_name=decision.policy_name,
        reason=f"[observe] would deny: {decision.reason}",
        reason_code=WOULD_DENY_REASON_CODE,
        remediation_message=None,
        column_violation=None,
    )
    return softened, True, decision.reason_code
