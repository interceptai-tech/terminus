"""Structured remediation feedback for denied Terminus decisions."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import PolicyDecision


class Remediation(BaseModel):
    """Agent-consumable guidance for self-correcting blocked SQL."""

    message: str
    suggestions: list[str] = Field(default_factory=list)
    header_value: str
    suggested_sql: str | None = None


def build_remediation(
    decision: PolicyDecision,
    parsed_sql: ParsedSQL,
    suggested_sql: str | None = None,
) -> Remediation | None:
    """Create remediation details for deny/review decisions.

    The output is intentionally based on parsed metadata only; raw SQL is never
    included in response bodies or headers. ``suggested_sql`` is a system-generated,
    already-re-validated rewrite (or None) supplied by the caller.
    """

    if decision.action == "allow":
        return None

    message = decision.remediation_message or decision.reason
    suggestions = _suggestions(parsed_sql, decision)
    header_value = _header_value(message, suggestions)

    return Remediation(
        message=message,
        suggestions=suggestions,
        header_value=header_value,
        suggested_sql=suggested_sql,
    )


def _suggestions(parsed_sql: ParsedSQL, decision: PolicyDecision) -> list[str]:
    violation = decision.column_violation
    if violation is not None:
        if violation.kind == "wildcard":
            allowed = ", ".join(violation.allowed) or "the approved columns"
            return [
                f"Enumerate the specific columns you need; '*' is not permitted on "
                f"column-restricted table {violation.table}.",
                f"Allowed columns: {allowed}.",
            ]
        if violation.kind == "disallowed":
            rejected = ", ".join(violation.denied)
            allowed = ", ".join(violation.allowed) or "the approved columns"
            return [
                f"Column(s) {rejected} are not allowed on {violation.table}.",
                f"Allowed columns: {allowed}.",
            ]
        if violation.kind == "insert_all":
            allowed = ", ".join(violation.allowed) or "the approved columns"
            return [
                f"List the specific columns in your INSERT; an INSERT without a column "
                f"list is not permitted on column-restricted table {violation.table}.",
                f"Allowed columns: {allowed}.",
            ]
        # kind == "qualify"
        ambiguous = ", ".join(violation.denied)
        return [
            f"Qualify columns as table.column when a restricted table is part of a join; "
            f"{ambiguous} was ambiguous.",
        ]

    if not parsed_sql.is_valid:
        return [
            "Submit a single syntactically valid SQL statement.",
            "Use a supported SQL dialect or provide the dialect parameter.",
        ]

    if parsed_sql.operation == "MULTI_STATEMENT":
        return ["Submit exactly one SQL statement per intercept request."]

    if parsed_sql.operation in {"DROP", "TRUNCATE", "ALTER", "CREATE"}:
        return [
            "Replace destructive DDL with an approved migration workflow.",
            "Request explicit human approval for schema-changing operations.",
        ]

    if parsed_sql.operation == "DELETE":
        return [
            "Use a soft-delete column when possible.",
            "If deletion is required, request a policy exception with human approval.",
        ]

    if parsed_sql.operation == "UPDATE" and not parsed_sql.has_where:
        return [
            "Add a selective WHERE clause to constrain affected rows.",
            "Target only policy-approved tables and columns.",
        ]

    if parsed_sql.risk_score >= 0.7:
        return ["Lower the query risk by narrowing scope or requesting approval."]

    return ["Rewrite the query to match an explicit allow policy."]


def _header_value(message: str, suggestions: list[str]) -> str:
    # The message interpolates attacker-influenced identifiers (quoted column/
    # table names from the SQL). A bare CR in a header value is the classic
    # response-splitting primitive; uvicorn/h11 rejects the header and turns a
    # valid 403 into a 500. Strip EVERY C0 control byte and DEL, not just \n,
    # before truncating.
    compact = re.sub(r"[\x00-\x1f\x7f]", " ", " ".join([message, *suggestions])).strip()
    return compact[:500]
