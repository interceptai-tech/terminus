"""Name-free signature facts (the input to build_signature).

RoleResolver and to_signature_facts live here alongside SignatureFacts.
The chokepoint (to_signature_facts) is the ONLY function in this subsystem
that receives real table/column names; everything it returns is name-free.
"""

from __future__ import annotations

from dataclasses import dataclass

from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import SchemaWhitelist
from terminus.signature import vocab


@dataclass(frozen=True)
class SignatureFacts:
    """Everything (name-free) needed to build a Signature.

    Every field is a primitive, an enum-like token from a controlled
    vocabulary, or a tuple of such tokens. There is NO free-text field, so
    this type structurally cannot carry a table name, column name, or literal.
    """

    operation: str
    has_where: bool
    has_aggregate: bool
    aggregate_only: bool
    has_subquery: bool
    has_union: bool
    join_count: int
    wildcard: str
    predicate_ops: tuple[str, ...]
    projection_roles: tuple[str, ...]
    predicate_roles: tuple[str, ...]
    table_roles: tuple[str, ...]
    security_flags: tuple[str, ...]
    smuggling_markers: tuple[str, ...]
    risk_score: float
    risk_reasons: tuple[str, ...]


class RoleResolver:
    """Answers role questions about real names using the schema whitelist.

    Constructed by the router from the ACTIVE PolicyEngine.whitelist at decision
    time, so a hot-reloaded policy can never make role attribution stale. This
    class and to_signature_facts() are the ONLY places real identifiers are seen.
    """

    def __init__(self, whitelist: SchemaWhitelist | None) -> None:
        self._whitelist = whitelist

    def restrictions_for(self, tables: list[str]) -> dict[str, set[str]]:
        return self._whitelist.column_restrictions(tables) if self._whitelist else {}

    def table_role(self, table: str) -> str:
        if self._whitelist is None:
            return "allowlisted"  # no whitelist configured -> treat as allowed
        if self._whitelist.disallowed_tables([table]):
            return "unlisted"
        if table in self._whitelist.column_restrictions([table]):
            return "restricted"
        return "allowlisted"

    def column_role(self, table: str | None, name: str, restrictions: dict[str, set[str]]) -> str:
        # `restrictions` maps ONLY column-restricted tables -> their allowed columns.
        if table is None:
            # Parser could not attribute the column. DELIBERATE fail-closed signal
            # (the policy engine already denies it); recorded as its own role.
            return "unattributed"
        if table not in restrictions:
            return "unrestricted"  # table has no column allowlist -> any column allowed
        # Table IS column-restricted: an allowed column is "allowlisted"; anything
        # else is "restricted" (a disallowed column on a restricted table). `name` is
        # already the parser's quote-aware canonical form (unquoted->lower, quoted
        # preserved), matched against the lowercased allowlist; re-lowering here would
        # fold a quoted case-variant ("EMAIL") back onto the allowlisted name and make
        # the role disagree with the policy deny (F10).
        return "allowlisted" if name in restrictions[table] else "restricted"


def to_signature_facts(
    parsed_sql: ParsedSQL,
    resolver: RoleResolver,
) -> SignatureFacts:
    """This is the only function in the entire signature subsystem permitted to
    receive real table/column names. All downstream types and functions operate
    exclusively on role classes and controlled vocabularies."""
    restrictions = resolver.restrictions_for(parsed_sql.tables)

    table_roles = {resolver.table_role(table) for table in parsed_sql.tables}

    # Source of truth for projection-vs-predicate: ColumnRef.position, tagged by
    # the parser when collect_signature_facts=True (see parser additions).
    projection_roles: set[str] = set()
    predicate_roles: set[str] = set()
    for ref in parsed_sql.columns:
        role = resolver.column_role(ref.table, ref.name, restrictions)  # name not copied out
        if ref.position == "projection":
            projection_roles.add(role)
        elif ref.position == "predicate":
            predicate_roles.add(role)
    if parsed_sql.has_aggregate:
        projection_roles.add("aggregate")

    if parsed_sql.has_bare_star:
        wildcard = "bare"
    elif parsed_sql.star_tables:
        wildcard = "qualified"
    else:
        wildcard = "none"

    flags = parsed_sql.security_flags
    security_flags = tuple(
        sorted(
            name for name, value in flags.model_dump().items() if isinstance(value, bool) and value
        )
    )
    smuggling_markers = tuple(
        sorted({kw for kw in flags.suspicious_keywords if kw in vocab.KNOWN_SMUGGLING_MARKERS})
    )

    return SignatureFacts(
        operation=parsed_sql.operation,
        has_where=parsed_sql.has_where,
        has_aggregate=parsed_sql.has_aggregate,
        aggregate_only=parsed_sql.aggregate_only,
        has_subquery=flags.has_hidden_subquery,
        has_union="union" in flags.suspicious_keywords,
        join_count=parsed_sql.join_count,
        wildcard=wildcard,
        predicate_ops=tuple(sorted(parsed_sql.predicate_ops)),
        projection_roles=tuple(sorted(projection_roles)),
        predicate_roles=tuple(sorted(predicate_roles)),
        table_roles=tuple(sorted(table_roles)),
        security_flags=security_flags,
        smuggling_markers=smuggling_markers,
        risk_score=parsed_sql.risk_score,
        risk_reasons=tuple(parsed_sql.risk_reasons),
    )
