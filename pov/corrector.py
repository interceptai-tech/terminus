"""Deterministic rule-based corrector for denies without a suggested_sql.

Only the UPDATE-without-WHERE case is rule-correctable against the example
policy: adding a selective WHERE lets allow_controlled_updates match. Column
violations are corrected by Terminus's own suggested_sql, so they are not handled
here. Everything else (destructive DDL, DELETE, injection, etc.) returns None,
which the harness counts as "not self-correctable by rule".
"""

from __future__ import annotations

from terminus.parser.sql_parser import parse_sql


def rule_based_correct(sql: str, dialect: str | None) -> str | None:
    """Return a corrected SQL string, or None if no rule applies."""
    parsed = parse_sql(sql, dialect=dialect)
    if parsed.operation == "UPDATE" and not parsed.has_where:
        # Add a selective WHERE so the update is no longer an unbounded mass write.
        return f"{sql.rstrip().rstrip(';')} WHERE id = 1"
    return None
