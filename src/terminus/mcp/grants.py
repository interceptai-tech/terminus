"""Execution grant and decision-outcome types for the MCP enforcement point.

The ExecutionGrant is the structural gate: the executor accepts only a grant, and a
grant is minted ONLY by decider.decide() on an allow. There is therefore no callable
path from a deny or an unresolved approval to execution.
"""

from __future__ import annotations

from dataclasses import dataclass

from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import PolicyDecision
from terminus.remediation.remediation import Remediation


@dataclass(frozen=True)
class ExecutionGrant:
    """Proof that a specific statement was allowed for a specific agent."""

    statement: str
    agent_id: str | None
    request_id: str


@dataclass(frozen=True)
class Allowed:
    """The engine allowed the statement; execute the grant immediately."""

    grant: ExecutionGrant
    # The ACTUAL parse and decision decide() made, carried through so audit never
    # has to re-derive (and risk contradicting) the outcome already given to the
    # client (see F-mcp-audit-redecision).
    parsed: ParsedSQL
    decision: PolicyDecision
    # Graduated-autonomy evidence (see terminus.policy.graduated). would_deny is
    # True only when this Allowed exists solely because an observe-mode agent's
    # deny was softened; would_deny_reason_code then carries the original,
    # pre-softening reason_code for audit. Both default to the enforce-mode
    # values so every non-graduated call site is unaffected.
    would_deny: bool = False
    would_deny_reason_code: str | None = None


@dataclass(frozen=True)
class Denied:
    """The engine denied the statement; return remediation, never execute."""

    reason: str
    reason_code: str
    remediation: Remediation | None
    parsed: ParsedSQL
    decision: PolicyDecision
    # See Allowed.would_deny. A still-Denied outcome is floor (never softened),
    # so this stays False/None for every real caller; present for symmetry.
    would_deny: bool = False
    would_deny_reason_code: str | None = None


@dataclass(frozen=True)
class NeedsApproval:
    """An allowed high-risk write held for human approval before execution."""

    grant: ExecutionGrant
    request_id: str
    reason: str
    parsed: ParsedSQL
    decision: PolicyDecision
    # See Allowed.would_deny.
    would_deny: bool = False
    would_deny_reason_code: str | None = None


DecisionOutcome = Allowed | Denied | NeedsApproval
