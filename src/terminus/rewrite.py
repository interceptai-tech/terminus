"""Safe SQL rewrites that let a denied agent self-correct.

Part of the trusted parsing/analysis layer alongside ``sql_parser``: this module
handles the raw SQL string and, like the parser, never logs it.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from terminus.parser.sql_parser import (
    _build_alias_map,
    _normalize_table_name,
    _resolve_qualifier,
)


def rewrite_wildcard(
    sql: str,
    restrictions: dict[str, set[str]],
    *,
    dialect: str | None = None,
) -> str | None:
    """Return a column-enumerated rewrite of a wildcard query, or None.

    Takes the raw SQL string because the rewrite must manipulate the sqlglot AST,
    which ParsedSQL does not carry. It is invoked only on a wildcard denial, so
    this reparse never happens on the common path. ``restrictions`` maps a
    normalized table to its allowed column set (from
    SchemaWhitelist.column_restrictions). Returns None when no deterministic,
    safe enumeration exists: a bare ``*`` over more than one table, a star on a
    non-restricted table, no star present, or any structural surprise.
    """
    if not restrictions:
        return None

    try:
        expression = sqlglot.parse_one(sql, read=dialect)
    except ParseError:
        return None

    # sqlglot.parse_one alone leaves identifier case exactly as written. parse_sql
    # normalizes via a dedicated pass, and this re-parse must match: without it,
    # a table name like `Public.Users` stays mixed-case and no longer matches the
    # (normalized, lowercased-or-per-dialect) keys of `restrictions`, so a wildcard
    # deny would silently stop producing a rewrite. Same dialect as the parse
    # above, so the fold matches whatever normalized `restrictions`.
    expression = normalize_identifiers(expression, dialect=dialect)

    if not isinstance(expression, exp.Select):
        return None

    # Guard: if any FROM or JOIN source is a derived table (subquery), we cannot
    # reliably attribute a bare `*` to a base table -- enumerating base columns
    # against a subquery alias would yield non-runnable SQL.  Subqueries that
    # appear only in WHERE/HAVING (e.g. correlated filters) do NOT trigger this
    # because they are not projection sources.
    from_clause = expression.args.get("from_")
    join_clauses = expression.args.get("joins") or []
    has_derived_table = any(
        node.find(exp.Subquery) is not None
        for node in [from_clause, *join_clauses]
        if node is not None
    )
    if has_derived_table:
        return None

    alias_map = _build_alias_map(expression)
    tables_in_query = {_normalize_table_name(t) for t in expression.find_all(exp.Table)}
    tables_in_query.discard("")
    single_table = next(iter(tables_in_query)) if len(tables_in_query) == 1 else None

    new_projections: list[exp.Expression] = []
    changed = False
    for projection in expression.expressions:
        if isinstance(projection, exp.Star):
            # bare `*`: safe only when exactly one table and it is restricted
            if single_table is not None and single_table in restrictions:
                for col in sorted(restrictions[single_table]):
                    new_projections.append(exp.column(col))
                changed = True
                continue
            return None
        if isinstance(projection, exp.Column) and projection.name == "*":
            # qualified `t.*`
            normalized = _resolve_qualifier(projection, alias_map)
            if normalized is None or normalized not in restrictions:
                return None  # cannot enumerate this star -> no fully-safe rewrite exists
            qualifier = projection.table
            for col in sorted(restrictions[normalized]):
                new_projections.append(exp.column(col, table=qualifier))
            changed = True
            continue
        new_projections.append(projection)

    if not changed:
        return None

    expression.set("expressions", new_projections)
    return expression.sql(dialect=dialect)
