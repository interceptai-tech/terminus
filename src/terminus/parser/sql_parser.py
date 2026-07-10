"""SQL parsing, risk scoring, and smuggling defense for Terminus.

This module intentionally never logs or returns the raw SQL text.
"""

from __future__ import annotations

import time
from typing import Any, cast

import sqlglot
from pydantic import BaseModel, Field
from sqlglot import exp
from sqlglot.dialects.dialect import Dialects
from sqlglot.errors import ParseError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from terminus.observability.metrics import observe_parser_latency


class SecurityFlags(BaseModel):
    """Security signals detected during AST traversal."""

    has_comments: bool = False
    has_nested_comments: bool = False
    has_hidden_subquery: bool = False
    has_smuggling_pattern: bool = False
    has_injection_function: bool = False
    suspicious_keywords: list[str] = Field(default_factory=list)


class ColumnRef(BaseModel):
    """A column reference resolved (best effort) to its table."""

    name: str
    table: str | None = None
    # Clause the column appeared in; populated only when collect_signature_facts.
    # The policy engine ignores this field. One of "projection" | "predicate" | "other".
    position: str = "other"


class ParsedSQL(BaseModel):
    """Normalized SQL metadata used by policy evaluation."""

    operation: str = Field(description="Top-level SQL operation")
    tables: list[str] = Field(default_factory=list)
    has_where: bool = False
    risk_score: float = Field(ge=0.0, le=1.0)
    is_valid: bool = True
    parse_error: str | None = None
    security_flags: SecurityFlags = Field(default_factory=SecurityFlags)
    columns: list[ColumnRef] = Field(default_factory=list)
    has_bare_star: bool = False
    star_tables: list[str] = Field(default_factory=list)
    risk_reasons: list[str] = Field(default_factory=list)
    predicate_ops: list[str] = Field(default_factory=list)
    has_aggregate: bool = False
    aggregate_only: bool = False
    join_count: int = 0
    # Tables written by an INSERT that names no column list (root, or nested in a
    # writable CTE). Such an INSERT writes every column implicitly, so on a
    # column-restricted table it fails closed. Explicit target columns are carried
    # as ordinary ColumnRefs in `columns`.
    insert_all_tables: list[str] = Field(default_factory=list)
    # Data-modifying operations (INSERT/UPDATE/DELETE/MERGE) nested in a CTE body.
    # A writable CTE under a read-rooted statement is classified by the top-level
    # `operation` only, so the operation-based policy rules never see the nested
    # write; this surfaces it so the engine can fail closed. Detected by CTE body
    # (not find_all over write nodes) so a top-level MERGE's WHEN arms are not
    # miscounted as nested writes.
    nested_write_operations: list[str] = Field(default_factory=list)


_DESTRUCTIVE_OPERATIONS = {"DROP", "TRUNCATE", "ALTER", "CREATE"}
_WRITE_OPERATIONS = {"DELETE", "UPDATE", "INSERT", "MERGE"}
SMUGGLING_PATTERNS = [
    "0x",
    "char(",
    "unhex(",
    "exec(",
    "execute(",
    "benchmark(",
    "sleep(",
    "waitfor",
]

# Injection / time-based / RCE function names, matched against AST FUNCTION nodes
# (never substrings). This is the enforced-by-default smuggling signal. Detection
# over function nodes means a TYPE name like ``varchar(255)`` (an exp.DataType, not
# a function) can never match, which is what fixes the old substring 'char(' false
# positive. Names are compared lowercased.
INJECTION_FUNCTION_NAMES = frozenset(
    {
        "pg_sleep",
        "sleep",
        "benchmark",
        "waitfor",
        "xp_cmdshell",
        "sp_executesql",
        "exec",
        "execute",
        "load_file",
        "pg_read_file",
        "pg_ls_dir",
        "dblink",
        "pg_terminate_backend",
        "pg_cancel_backend",
    }
)


def _function_name(node: exp.Expression) -> str | None:
    """Lowercased bare callable name for a function-call node, else None.

    Uses ``node.name`` (the terminal identifier text), which strips quoting and
    schema qualifiers, so ``"pg_sleep"(...)``, ``pg_catalog.pg_sleep(...)`` and
    ``PG_SLEEP(...)`` all resolve to ``pg_sleep`` and cannot evade the denylist.
    An ``exp.DataType`` (e.g. ``varchar(255)``) is not an ``exp.Func``, so type
    names never resolve to a function name.
    """
    if isinstance(node, exp.Anonymous):  # unknown functions: pg_sleep, benchmark, ...
        return node.name.lower() or None
    if isinstance(node, exp.Func):
        try:
            return (node.sql_name() or node.name or "").lower() or None
        except Exception:
            return None
    return None


# Fail-closed parse bounds. MAX_SQL_LENGTH is the default character cap; the router
# passes settings.max_sql_length. Over-cap input is denied BEFORE the CPU-heavy
# parse so a single large or pathological statement cannot block the event loop.
# KNOWN_DIALECTS lets us reject an unknown dialect deterministically instead of
# letting sqlglot raise a ValueError that would 500 the request.
MAX_SQL_LENGTH = 16_384
KNOWN_DIALECTS: frozenset[str] = frozenset(d.value.lower() for d in Dialects if d.value)


def _invalid(reason: str, detail: str) -> ParsedSQL:
    """Build the fail-closed INVALID result (an audited deny); never raises.

    ``reason`` is the low-cardinality reason_code tag (``invalid_sql`` |
    ``oversize_sql``); ``detail`` is a name-free diagnostic (an exception class
    name or a short tag), never raw SQL.
    """
    return ParsedSQL(
        operation="INVALID",
        risk_score=1.0,
        is_valid=False,
        parse_error=detail,
        security_flags=SecurityFlags(has_smuggling_pattern=True),
        risk_reasons=[reason],
    )


def parse_sql(
    sql: str,
    *,
    dialect: str | None = None,
    normalize_dialect: str | None = None,
    collect_signature_facts: bool = False,
    max_length: int = MAX_SQL_LENGTH,
) -> ParsedSQL:
    """Parse SQL with timing and security inspection.

    Fail-closed and cost-bounded. An oversize, unknown-dialect, or otherwise
    unparseable statement returns an INVALID result (an audited deny), never
    raises: the whole body is wrapped so no parser or analysis error (ParseError,
    a bad-dialect ValueError, a deep-nesting RecursionError, or any future sqlglot
    internal error) can 500 the request. The size cap runs first so a pathological
    statement never reaches the CPU-heavy parse and cannot block the event loop.

    ``dialect`` controls PARSE syntax only (quote characters, grammar). Identifier
    normalization -- the case-fold that whitelist/policy matching depends on --
    uses ``normalize_dialect`` when given, else falls back to ``dialect``. Callers
    that accept an untrusted per-request dialect (e.g. the API payload) MUST pass
    the trusted deployment dialect as ``normalize_dialect`` explicitly, so an
    attacker cannot pick a case-insensitive dialect to fold a quoted case-variant
    identifier onto a distinct whitelisted object and bypass the whitelist.
    """
    start = time.perf_counter()
    try:
        if len(sql) > max_length:
            return _invalid("oversize_sql", "oversize")
        if dialect and dialect.lower() not in KNOWN_DIALECTS:
            return _invalid("invalid_sql", "unsupported_dialect")

        try:
            parsed_expressions = sqlglot.parse(sql, read=dialect)
        except ParseError as exc:
            return _invalid("invalid_sql", _sanitize_parse_error(exc))

        expressions = [cast(exp.Expression, e) for e in parsed_expressions if e is not None]
        # F10c: canonicalize every identifier per the TRUSTED deployment dialect
        # (unquoted folded per the dialect's case rule, quoted handled per its
        # case-sensitivity). norm_dialect defaults to `dialect` so internal/test
        # callers that pass a single `dialect=` keep working, but a caller with an
        # untrusted per-request dialect must pass `normalize_dialect` explicitly --
        # see the docstring. After this, extraction reads canonical `.name`. Inside
        # the fail-closed try: a normalize error yields invalid_sql, never a 500.
        norm_dialect = normalize_dialect if normalize_dialect is not None else dialect
        expressions = [normalize_identifiers(e, dialect=norm_dialect) for e in expressions]
        if not expressions:
            return _invalid("invalid_sql", "empty_statement")
        if len(expressions) > 1:
            return ParsedSQL(
                operation="MULTI_STATEMENT",
                tables=_extract_tables_from_many(expressions),
                has_where=any(_has_where(e) for e in expressions),
                risk_score=1.0,
                security_flags=SecurityFlags(has_smuggling_pattern=True),
                risk_reasons=["multi_statement"],
            )

        expression = expressions[0]
        security_flags = _detect_smuggling(expression)
        operation = _operation_name(expression)
        has_where = _has_where(expression)
        tables = _extract_tables(expression)
        columns, has_bare_star, star_tables = _extract_columns(
            expression, tables, collect_facts=collect_signature_facts
        )

        predicate_ops: list[str] = []
        has_aggregate = False
        aggregate_only = False
        join_count = 0
        if collect_signature_facts:
            predicate_ops = _extract_predicate_ops(expression)
            has_aggregate, aggregate_only = _aggregate_facts(expression)
            join_count = len(list(expression.find_all(exp.Join)))

        risk_score, risk_reasons = _risk_assessment(
            operation=operation,
            has_where=has_where,
            tables=tables,
            security_flags=security_flags,
            has_wildcard=has_bare_star or bool(star_tables),
        )

        insert_all_tables: list[str] = []
        for insert in expression.find_all(exp.Insert):
            table, _cols, has_list = _insert_node_target(insert)
            if table is not None and not has_list:
                insert_all_tables.append(table)

        # A data-modifying statement nested in a CTE body is invisible to the
        # top-level `operation`. Surface these so the policy engine can fail
        # closed on writable CTEs. Scan CTE bodies specifically (not find_all over
        # write nodes): a top-level MERGE decomposes into Insert/Update WHEN-arm
        # nodes that would otherwise be miscounted as nested writes.
        nested_write_operations = sorted(
            {
                _operation_name(cte.this)
                for cte in expression.find_all(exp.CTE)
                if isinstance(cte.this, (exp.Insert, exp.Update, exp.Delete, exp.Merge))
            }
        )

        return ParsedSQL(
            operation=operation,
            tables=tables,
            has_where=has_where,
            risk_score=risk_score,
            is_valid=True,
            security_flags=security_flags,
            columns=columns,
            has_bare_star=has_bare_star,
            star_tables=star_tables,
            risk_reasons=risk_reasons,
            predicate_ops=predicate_ops,
            has_aggregate=has_aggregate,
            aggregate_only=aggregate_only,
            join_count=join_count,
            insert_all_tables=insert_all_tables,
            nested_write_operations=nested_write_operations,
        )
    except Exception as exc:  # never 500: any parser/analysis failure -> audited deny
        return _invalid("invalid_sql", exc.__class__.__name__)
    finally:
        observe_parser_latency(time.perf_counter() - start)


def _detect_smuggling(expression: exp.Expression) -> SecurityFlags:
    """Walk AST looking for comment smuggling, hidden subqueries, and union-based bypasses."""
    flags = SecurityFlags()
    sql_str = str(expression).lower()

    if "--" in sql_str or "/*" in sql_str:
        flags.has_comments = True
    if "/*" in sql_str and "*/" in sql_str and sql_str.count("/*") > 1:
        flags.has_nested_comments = True

    # Single AST walk detects both hidden subqueries/set-ops and injection
    # function calls. Injection detection is by function-node NAME, not a substring
    # scan of the regenerated SQL: that is what makes `varchar(255)` (a DataType)
    # safe while `pg_sleep(...)` (a function) is caught.
    subquery_types = (exp.Subquery, exp.Union, exp.Intersect, exp.Except)
    for found in expression.walk():
        if isinstance(found, subquery_types):
            flags.has_hidden_subquery = True
            flags.suspicious_keywords.append(found.__class__.__name__.lower())
        name = _function_name(cast(exp.Expression, found))
        if name is not None and name in INJECTION_FUNCTION_NAMES:
            flags.has_injection_function = True
            flags.suspicious_keywords.append(name)

    if (
        flags.has_injection_function
        or flags.has_comments
        or flags.has_nested_comments
        or flags.has_hidden_subquery
    ):
        flags.has_smuggling_pattern = True

    return flags


def _operation_name(expression: exp.Expression) -> str:
    if isinstance(expression, exp.Select):
        return "SELECT"
    if isinstance(expression, exp.Update):
        return "UPDATE"
    if isinstance(expression, exp.Delete):
        return "DELETE"
    if isinstance(expression, exp.Insert):
        return "INSERT"
    if isinstance(expression, exp.Merge):
        return "MERGE"
    if isinstance(expression, exp.Drop):
        return "DROP"
    if isinstance(expression, exp.Alter):
        return "ALTER"
    if isinstance(expression, exp.Create):
        return "CREATE"
    if expression.key:
        return expression.key.upper()
    return expression.__class__.__name__.upper()


def _extract_tables_from_many(expressions: list[exp.Expression]) -> list[str]:
    tables: set[str] = set()
    for expression in expressions:
        tables.update(_extract_tables(expression))
    return sorted(tables)


def _extract_tables(expression: exp.Expression) -> list[str]:
    tables = {_normalize_table_name(table) for table in expression.find_all(exp.Table)}
    return sorted(table for table in tables if table)


def _normalize_table_name(table: exp.Table) -> str:
    parts = [_to_optional_string(table.catalog), _to_optional_string(table.db), table.name]
    return ".".join(part for part in parts if part)


def _to_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    string_value = str(value).strip()
    return string_value or None


def _build_alias_map(expression: exp.Expression) -> dict[str, str]:
    """Map each table alias, short name, and normalized name to the normalized table."""
    alias_map: dict[str, str] = {}
    for table in expression.find_all(exp.Table):
        normalized = _normalize_table_name(table)
        if not normalized:
            continue
        alias_map[normalized] = normalized
        if table.name:
            short_key = table.name
            if short_key in alias_map and alias_map[short_key] != normalized:
                del alias_map[short_key]  # ambiguous short name across tables -> refuse to resolve
            else:
                alias_map[short_key] = normalized
        if table.alias:
            alias_map[table.alias] = normalized
    return alias_map


def _column_qualifier(column: exp.Column) -> tuple[str | None, str | None]:
    """Return (full normalized qualifier, short table token) for a column."""
    short = _to_optional_string(column.table)
    db = _to_optional_string(column.db)
    catalog = _to_optional_string(column.catalog)
    parts = [catalog, db, short]
    full = ".".join(part for part in parts if part) or None
    return full, short


def _resolve_qualifier(column: exp.Column, alias_map: dict[str, str]) -> str | None:
    full, short = _column_qualifier(column)
    if full and full in alias_map:
        return alias_map[full]
    if short and short in alias_map:
        return alias_map[short]
    return None


def _insert_node_target(insert: exp.Insert) -> tuple[str | None, list[str], bool]:
    """For one INSERT node, return (target_table, explicit_columns, has_explicit_list).

    The target table is ``Schema.this`` (with a column list) or ``Insert.this``
    (without); it is UNAMBIGUOUS even for ``INSERT ... SELECT`` (two tables), so
    callers must NOT fall back to single-table attribution for these columns.
    ``has_explicit_list`` is False when the INSERT names no columns (it writes every
    column implicitly).
    """
    target = insert.this
    if isinstance(target, exp.Schema):  # INSERT INTO t (a, b, ...) ...
        table_node = target.this
        table = _normalize_table_name(table_node) if isinstance(table_node, exp.Table) else None
        idents = [i.name for i in target.expressions if isinstance(i, exp.Identifier)]
        return table, idents, bool(idents)
    if isinstance(target, exp.Table):  # INSERT INTO t VALUES / SELECT / DEFAULT VALUES
        return _normalize_table_name(target), [], False
    return None, [], False  # exotic target: no usable column list


def _extract_columns(
    expression: exp.Expression, tables: list[str], *, collect_facts: bool = False
) -> tuple[list[ColumnRef], bool, list[str]]:
    """Extract column references and wildcard facts, attributing columns to tables.

    Conservative by construction: any column that cannot be confidently attributed
    yields table=None, which the policy engine fails closed on when a restricted
    table is present.
    """
    alias_map = _build_alias_map(expression)

    # An output alias is only visible in the ORDER BY of its OWN SELECT block, so
    # the set of skippable ORDER BY alias references is computed PER BLOCK. A
    # statement-wide alias set would let an OUTER alias suppress an INNER
    # subquery's ORDER BY reference to a base column of the same name (a column
    # allowlist bypass), and vice versa.
    alias_order_by_ids: set[int] = set()
    for select in expression.find_all(exp.Select):
        order_node = select.args.get("order")
        if order_node is None:
            continue
        # Match aliases quote-awarely (same key as column extraction): a quoted
        # output alias `"SSN"` and a quoted `ORDER BY "ssn"` are DISTINCT identifiers
        # in Postgres, so the ORDER BY term must not be suppressed as an alias
        # reference -- otherwise it silently skips a restricted base-column read (a
        # blind-oracle sort channel). Both sides read the already-canonical
        # identifier (normalize_identifiers ran up front) so a true same-identifier
        # match suppresses.
        block_aliases = {
            projection.alias
            for projection in select.expressions
            if isinstance(projection, exp.Alias) and projection.alias
        }
        if not block_aliases:
            continue
        for order_col in order_node.find_all(exp.Column):
            if order_col.find_ancestor(exp.Select) is not select:
                continue  # a column in a nested subquery inside this ORDER BY
            col_full, col_short = _column_qualifier(order_col)
            if col_full is None and col_short is None and order_col.name in block_aliases:
                alias_order_by_ids.add(id(order_col))

    # Build a set of AST node identities for columns that are projection VALUES
    # (the data being selected), not alias names or predicate references.
    # For `SELECT id AS user_id`, `id` is the projection value; `user_id` is
    # the alias. For `SELECT password_hash`, `password_hash` is the projection
    # value. We use id() so the check is O(1) and identity-based (not name-based).
    projection_value_ids: set[int] = set()
    for select in expression.find_all(exp.Select):
        for projection in select.expressions:
            # The value side: strip alias wrapper if present, then collect all
            # Column nodes under it (handles expressions like COALESCE(a, b) AS x).
            proj_value = projection.this if isinstance(projection, exp.Alias) else projection
            for col in proj_value.find_all(exp.Column):
                projection_value_ids.add(id(col))

    predicate_value_ids: set[int] = set()
    if collect_facts:
        for clause_type in (exp.Where, exp.Having):
            for clause_node in expression.find_all(clause_type):
                for col in clause_node.find_all(exp.Column):
                    predicate_value_ids.add(id(col))

    # `tables` is the deduplicated list from _extract_tables(), so a self-join
    # (same table, multiple aliases) has len == 1 here, enabling attribution.
    single_table = tables[0] if len(tables) == 1 else None

    has_bare_star = False
    for star in expression.find_all(exp.Star):
        if star.find_ancestor(exp.Func) is not None:
            continue  # COUNT(*) and other aggregate stars leak no column values
        if isinstance(star.parent, exp.Column):
            continue  # qualified `t.*` is handled in the column loop below
        has_bare_star = True

    columns: list[ColumnRef] = []
    star_tables: set[str] = set()
    for column in expression.find_all(exp.Column):
        # `t.*` has a Star leaf; `column.name` is `*` for it. Every other column's
        # name is the canonical identifier (already folded by normalize_identifiers).
        name = column.name
        if name == "*":
            if column.find_ancestor(exp.Func) is not None:
                continue  # COUNT(t.*)
            resolved = _resolve_qualifier(column, alias_map)
            if resolved is not None:
                star_tables.add(resolved)
            else:
                has_bare_star = True  # unresolvable t.* -> conservative bare star
            continue
        # Skip a column ONLY when it is a genuine downstream alias reference: an
        # ORDER BY column that resolves to an output alias OF ITS OWN SELECT block
        # (alias_order_by_ids already encodes bare + name-in-block-aliases + owned
        # by that block's ORDER BY). Everything else -- WHERE / JOIN ON / GROUP BY
        # / HAVING references, and any cross-block name collision -- is a real
        # base-column access and is checked against the allowlist. This closes the
        # `SELECT id AS ssn ... WHERE ssn = ...` bypass and the nested-subquery
        # variant where an outer alias would suppress an inner `ORDER BY ssn`.
        full, short = _column_qualifier(column)
        if id(column) in alias_order_by_ids and id(column) not in projection_value_ids:
            continue
        if full is None and short is None:
            table = single_table
        else:
            table = _resolve_qualifier(column, alias_map)
        # Each Column AST node lives in exactly one clause, so the projection and
        # predicate identity sets are disjoint; the elif ordering is unambiguous.
        position = "other"
        if collect_facts:
            if id(column) in projection_value_ids:
                position = "projection"
            elif id(column) in predicate_value_ids:
                position = "predicate"
        columns.append(ColumnRef(name=name, table=table, position=position))

    # INSERT target columns are exp.Identifier under exp.Schema, invisible to the
    # exp.Column walk above. Walk EVERY INSERT node (root, or nested in a writable
    # CTE) so a restricted-column write cannot hide inside a CTE, and attribute each
    # to its (unambiguous) target table so the column allowlist applies to writes
    # exactly as it does to UPDATE SET. Tagged position="other" like SET columns, so
    # they never enter the name-free signature roles.
    for insert in expression.find_all(exp.Insert):
        insert_table, insert_cols, _has_list = _insert_node_target(insert)
        for insert_col in insert_cols:
            columns.append(ColumnRef(name=insert_col, table=insert_table, position="other"))

    return columns, has_bare_star, sorted(star_tables)


def _has_where(expression: exp.Expression) -> bool:
    return expression.find(exp.Where) is not None


_PREDICATE_OP_MAP: dict[type, str] = {
    exp.EQ: "EQ",
    exp.NEQ: "NEQ",
    exp.GT: "GT",
    exp.GTE: "GTE",
    exp.LT: "LT",
    exp.LTE: "LTE",
    exp.Like: "LIKE",
    exp.ILike: "ILIKE",
    exp.In: "IN",
    exp.Between: "BETWEEN",
    exp.Is: "IS",
}
_regexp_like = getattr(exp, "RegexpLike", None)
if _regexp_like is not None:  # dialect-dependent node, present in current sqlglot
    _PREDICATE_OP_MAP[_regexp_like] = "REGEXP"

# Logical/structural nodes that are not comparison predicates.
_PREDICATE_IGNORE = (exp.And, exp.Or, exp.Not, exp.Paren, exp.Connector)


def _extract_predicate_ops(expression: exp.Expression) -> list[str]:
    """Operator CLASSES used in WHERE/HAVING, mapped to a fixed vocabulary.

    Anything that is a comparison/predicate node but not explicitly mapped
    collapses to "OTHER" so the vocabulary stays closed (no raw SQL leaks).
    """
    ops: set[str] = set()
    for clause in (exp.Where, exp.Having):
        for node in expression.find_all(clause):
            for sub in node.walk():
                cls = type(sub)
                if cls in _PREDICATE_OP_MAP:
                    ops.add(_PREDICATE_OP_MAP[cls])
                elif isinstance(sub, (exp.Binary, exp.Predicate)) and not isinstance(
                    sub, _PREDICATE_IGNORE
                ):
                    ops.add("OTHER")
    return sorted(ops)


def _aggregate_facts(expression: exp.Expression) -> tuple[bool, bool]:
    """Return (has_aggregate, aggregate_only) over all SELECT projections."""
    # Only consider top-level SELECTs. A subquery's SELECT has a Select ancestor,
    # so an aggregate inside a WHERE-subquery must not flip the outer query's shape.
    selects = [
        select
        for select in expression.find_all(exp.Select)
        if select.find_ancestor(exp.Select) is None
    ]
    if not selects:
        return False, False
    has_aggregate = False
    all_aggregate = True
    any_projection = False
    for select in selects:
        for projection in select.expressions:
            value = projection.this if isinstance(projection, exp.Alias) else projection
            any_projection = True
            if isinstance(value, exp.AggFunc) or value.find(exp.AggFunc) is not None:
                has_aggregate = True
            else:
                all_aggregate = False
    return has_aggregate, (has_aggregate and all_aggregate and any_projection)


def _risk_score(
    *,
    operation: str,
    has_where: bool,
    tables: list[str],
    security_flags: SecurityFlags,
) -> float:
    if security_flags.has_smuggling_pattern:
        return 1.0
    if security_flags.has_hidden_subquery or security_flags.has_nested_comments:
        return 0.95

    if operation in {"INVALID", "MULTI_STATEMENT"}:
        return 1.0
    if operation in _DESTRUCTIVE_OPERATIONS:
        return 1.0
    if operation == "DELETE":
        return 0.9 if has_where else 1.0
    if operation == "UPDATE":
        return 0.45 if has_where else 0.85
    if operation == "MERGE":
        return 0.7
    if operation == "INSERT":
        return 0.35
    if operation == "SELECT":
        return 0.05 if tables else 0.1
    return 0.5 if operation in _WRITE_OPERATIONS else 0.8


def _risk_assessment(
    *,
    operation: str,
    has_where: bool,
    tables: list[str],
    security_flags: SecurityFlags,
    has_wildcard: bool,
) -> tuple[float, list[str]]:
    """Compute the risk score plus a structured, low-cardinality list of reasons."""
    reasons: list[str] = []
    if security_flags.has_comments:
        reasons.append("comments")
    if security_flags.has_nested_comments:
        reasons.append("nested_comments")
    if security_flags.has_hidden_subquery:
        reasons.append("hidden_subquery")
    if security_flags.has_smuggling_pattern:
        reasons.append("smuggling_pattern")
    if security_flags.has_injection_function:
        reasons.append("injection_function")
    if operation in _DESTRUCTIVE_OPERATIONS:
        reasons.append("destructive_operation")
    if operation in {"DELETE", "UPDATE"} and not has_where:
        reasons.append("no_where_clause")
    if has_wildcard:
        reasons.append("wildcard_select")
    score = _risk_score(
        operation=operation,
        has_where=has_where,
        tables=tables,
        security_flags=security_flags,
    )
    return score, reasons


def _sanitize_parse_error(exc: ParseError) -> str:
    return exc.__class__.__name__
