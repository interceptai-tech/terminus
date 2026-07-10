"""Signature model, deterministic fingerprint, and fail-closed privacy guard.

This module operates ONLY on name-free SignatureFacts / Signature objects. It
never receives real table or column names.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import PolicyDecision
from terminus.signature import vocab
from terminus.signature.facts import RoleResolver, SignatureFacts, to_signature_facts

# The fingerprint ALGORITHM version. Bump only when the canonical fingerprint
# input (see query_fingerprint) changes. Records of a different fingerprint_version
# are not comparable and are skipped by the matcher/store.
FINGERPRINT_VERSION = "1"


class PrivacyGuardError(Exception):
    """Raised when a Signature contains a token outside the controlled vocabulary."""

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"signature privacy guard tripped on field: {field}")


class SignatureStructure(BaseModel):
    has_where: bool
    has_aggregate: bool
    aggregate_only: bool
    has_subquery: bool
    has_union: bool
    join_count: int
    wildcard: str
    predicate_ops: list[str] = Field(default_factory=list)
    projection_roles: list[str] = Field(default_factory=list)
    predicate_roles: list[str] = Field(default_factory=list)
    table_roles: list[str] = Field(default_factory=list)


class Signature(BaseModel):
    schema_version: str = FINGERPRINT_VERSION
    query_fingerprint: str
    operation: str
    decision: str
    reason_code: str
    risk_score: float
    risk_reasons: list[str] = Field(default_factory=list)
    technique: str | None = None
    structure: SignatureStructure
    security_flags: list[str] = Field(default_factory=list)
    smuggling_markers: list[str] = Field(default_factory=list)
    emitted_at: str


def query_fingerprint(facts: SignatureFacts, technique: str | None) -> str:
    """sha256 over the canonical abstract structure ONLY (spec section 8.1).

    Excludes risk_score, decision, reason_code, emitted_at, schema_version so the
    hash groups by query shape and technique regardless of outcome or timing.
    """
    # List fields are sorted so the fingerprint is order-independent; these fields are sets
    # (role classes, operator classes, marker/flag names) and order carries no meaning.
    canonical = {
        "operation": facts.operation,
        "structure": {
            "has_where": facts.has_where,
            "has_aggregate": facts.has_aggregate,
            "aggregate_only": facts.aggregate_only,
            "has_subquery": facts.has_subquery,
            "has_union": facts.has_union,
            "join_count": facts.join_count,
            "wildcard": facts.wildcard,
            "predicate_ops": sorted(facts.predicate_ops),
            "projection_roles": sorted(facts.projection_roles),
            "predicate_roles": sorted(facts.predicate_roles),
            "table_roles": sorted(facts.table_roles),
        },
        "technique": technique,
        "security_flags": sorted(facts.security_flags),
        "smuggling_markers": sorted(facts.smuggling_markers),
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _assert_privacy(signature: Signature) -> None:
    """Fail closed: raise if any token is outside its controlled vocabulary.

    operation is a SQL keyword (never an identifier) and risk_reasons are
    parser-controlled, so they are intentionally not validated here. This guard
    exists to catch a real table/column name leaking into a role/op/marker list.
    """
    s = signature.structure
    checks: list[tuple[str, list[str], frozenset[str]]] = [
        ("structure.wildcard", [s.wildcard], vocab.WILDCARDS),
        ("structure.predicate_ops", s.predicate_ops, vocab.PREDICATE_OPS),
        ("structure.projection_roles", s.projection_roles, vocab.COLUMN_ROLES),
        ("structure.predicate_roles", s.predicate_roles, vocab.COLUMN_ROLES),
        ("structure.table_roles", s.table_roles, vocab.TABLE_ROLES),
        ("security_flags", signature.security_flags, vocab.SECURITY_FLAG_NAMES),
        ("smuggling_markers", signature.smuggling_markers, vocab.KNOWN_SMUGGLING_MARKERS),
    ]
    for field, values, allowed in checks:
        for value in values:
            if value not in allowed:
                raise PrivacyGuardError(field)
    if signature.technique is not None and signature.technique not in vocab.TECHNIQUES:
        raise PrivacyGuardError("technique")


_DESTRUCTIVE_DDL = {"DROP", "TRUNCATE", "ALTER", "CREATE"}


def _has_role(roles: tuple[str, ...], *targets: str) -> bool:
    """True if any role in `roles` is one of `targets`.

    Written explicitly: `("a" or "b") in roles` is a real bug (it tests only "a").
    """
    return any(role in targets for role in roles)


def _label_technique(facts: SignatureFacts) -> str | None:
    """Label the query technique. First match wins; order encodes priority."""
    if facts.smuggling_markers or "has_smuggling_pattern" in facts.security_flags:
        return "smuggling"
    if (
        facts.aggregate_only
        and "restricted" in facts.predicate_roles
        and "restricted" not in facts.projection_roles
    ):
        return "aggregate_oracle_probe"
    if facts.wildcard != "none" and _has_role(facts.table_roles, "restricted", "allowlisted"):
        return "wildcard_exfiltration"
    if "restricted" in facts.projection_roles:
        return "disallowed_column_access"
    if facts.operation in _DESTRUCTIVE_DDL or (
        facts.operation in {"DELETE", "UPDATE"} and not facts.has_where
    ):
        return "destructive_unbounded"
    if "unlisted" in facts.table_roles:
        return "unlisted_table_access"
    return None


def build_signature(facts: SignatureFacts, decision: PolicyDecision) -> Signature:
    """Assemble a Signature from name-free facts and the decision outcome."""
    technique = _label_technique(facts)
    return Signature(
        query_fingerprint=query_fingerprint(facts, technique),
        operation=facts.operation,
        decision=decision.action,
        # reason_code is a fixed policy-engine enum (schema_whitelist,
        # column_whitelist, risk_threshold, policy_rule, default, ...), so it is
        # name-free and not vocab-checked by _assert_privacy. Operator-controlled
        # names live on policy_id/policy_name/reason, which are deliberately NOT
        # copied into the signature. Keep it that way.
        reason_code=decision.reason_code,
        risk_score=facts.risk_score,
        risk_reasons=list(facts.risk_reasons),
        technique=technique,
        structure=SignatureStructure(
            has_where=facts.has_where,
            has_aggregate=facts.has_aggregate,
            aggregate_only=facts.aggregate_only,
            has_subquery=facts.has_subquery,
            has_union=facts.has_union,
            join_count=facts.join_count,
            wildcard=facts.wildcard,
            predicate_ops=list(facts.predicate_ops),
            projection_roles=list(facts.projection_roles),
            predicate_roles=list(facts.predicate_roles),
            table_roles=list(facts.table_roles),
        ),
        security_flags=list(facts.security_flags),
        smuggling_markers=list(facts.smuggling_markers),
        emitted_at=datetime.now(UTC).isoformat(),
    )


def fingerprint_for(
    parsed_sql: ParsedSQL, resolver: RoleResolver
) -> tuple[str, SignatureFacts, str | None]:
    """Compute (fingerprint, facts, technique) for a query, decision-independent.

    Shared by the matcher (every query when matching is on) and the emit path
    (gated queries). The fingerprint depends only on structural facts + technique,
    never on the allow/deny outcome.
    """
    facts = to_signature_facts(parsed_sql, resolver)
    technique = _label_technique(facts)
    return query_fingerprint(facts, technique), facts, technique
