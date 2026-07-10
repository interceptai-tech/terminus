"""Controlled vocabularies: the ONLY string values a signature may contain.

If a value is not in one of these sets, the privacy guard treats it as a
potential identifier leak and drops the signature.
"""

from __future__ import annotations

from terminus.parser.sql_parser import SMUGGLING_PATTERNS

TABLE_ROLES: frozenset[str] = frozenset({"restricted", "allowlisted", "unlisted"})
COLUMN_ROLES: frozenset[str] = frozenset(
    {"restricted", "allowlisted", "unrestricted", "aggregate", "unattributed"}
)
WILDCARDS: frozenset[str] = frozenset({"none", "bare", "qualified"})
PREDICATE_OPS: frozenset[str] = frozenset(
    {
        "EQ",
        "NEQ",
        "LT",
        "GT",
        "LTE",
        "GTE",
        "LIKE",
        "ILIKE",
        "IN",
        "BETWEEN",
        "IS",
        "REGEXP",
        "OTHER",
    }
)
SECURITY_FLAG_NAMES: frozenset[str] = frozenset(
    {
        "has_comments",
        "has_nested_comments",
        "has_hidden_subquery",
        "has_smuggling_pattern",
        "has_injection_function",
    }
)
TECHNIQUES: frozenset[str] = frozenset(
    {
        "smuggling",
        "aggregate_oracle_probe",
        "wildcard_exfiltration",
        "disallowed_column_access",
        "destructive_unbounded",
        "unlisted_table_access",
    }
)
# Derived from the parser's fixed pattern list so the two never drift.
KNOWN_SMUGGLING_MARKERS: frozenset[str] = frozenset(SMUGGLING_PATTERNS)
