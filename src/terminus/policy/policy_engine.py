"""Policy loading and evaluation for Terminus."""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Literal

import structlog
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from sqlglot import exp
from sqlglot.dialects.dialect import Dialect

from terminus.config.settings import get_settings
from terminus.parser.sql_parser import MAX_SQL_LENGTH, ParsedSQL, parse_sql
from terminus.rewrite import rewrite_wildcard

PolicyAction = Literal["allow", "deny", "review"]

_log = structlog.get_logger("terminus.policy")


def _is_glob(name: str) -> bool:
    return any(ch in name for ch in "*?[")


def _normalize_config_identifier(name: str, dialect: str) -> str:
    """Fold one config identifier per the deployment dialect (treated as unquoted).

    Generic/Postgres -> lowercase (today's behavior), Snowflake -> uppercase,
    case-insensitive dialects -> lowercase, case-sensitive -> unchanged.
    """
    ident = exp.to_identifier(name, quoted=False)
    return Dialect.get_or_raise(dialect or None).normalize_identifier(ident).name


def _normalize_config_pattern(pattern: str, dialect: str) -> str:
    """Fold the literal parts of a possibly-globbed dotted config pattern."""
    return ".".join(
        part if part == "*" else _normalize_config_identifier(part, dialect)
        for part in pattern.split(".")
    )


class WhitelistTable(BaseModel):
    """An object-form whitelist entry that can restrict columns."""

    model_config = ConfigDict(extra="forbid")

    name: str
    columns: list[str] | None = None  # None -> all columns allowed


class PolicyConditions(BaseModel):
    """Optional query-shape conditions for a policy rule."""

    has_where: bool | None = None


class PolicyLimits(BaseModel):
    """Optional limits attached to a policy rule.

    max_destructive_risk_score is ENFORCED (risk-threshold deny).
    max_queries_per_minute is parsed for forward compatibility but NOT
    enforced in v0: the global TERMINUS_RATE_LIMIT_PER_MINUTE is the only
    active rate limit, and the governance loader logs
    policy_limit_not_enforced for any rule that sets it.
    """

    max_queries_per_minute: int | None = Field(default=None, gt=0)
    max_destructive_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)


class PolicyRemediation(BaseModel):
    """Remediation metadata from policy.yaml."""

    message: str | None = None
    auto_suggest: bool = False


class PolicyMatch(BaseModel):
    """Match criteria for a policy rule."""

    operation: list[str] | None = None
    tables: list[str] | None = None
    agent_ids: list[str] | None = None
    conditions: PolicyConditions | None = None


class PolicyRule(BaseModel):
    """A single ordered policy rule."""

    id: str
    name: str
    priority: int = 0
    match: PolicyMatch = Field(default_factory=PolicyMatch)
    action: PolicyAction
    limits: PolicyLimits | None = None
    remediation: PolicyRemediation | None = None


class PolicyConfig(BaseModel):
    """Top-level policy.yaml schema."""

    model_config = ConfigDict(extra="forbid")

    version: str
    default_action: PolicyAction = "deny"
    default_remediation_message: str = "Operation blocked by Terminus."
    policies: list[PolicyRule] = Field(default_factory=list)

    _dialect: str = PrivateAttr(default="")

    @model_validator(mode="after")
    def _capture_dialect(self, info: ValidationInfo) -> PolicyConfig:
        self._dialect = (info.context or {}).get("dialect", "") if info else ""
        return self


class SchemaWhitelist(BaseModel):
    """Default-deny allow-list of referenceable tables (schema_whitelist.yaml).

    Evaluated before policy rules. Table entries are either a plain string (a
    name or glob, all columns allowed) or a single-key mapping whose value may
    carry a ``columns`` list. Globs are always all-columns.
    """

    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    enabled: bool = True
    tables: list[str | WhitelistTable] = Field(default_factory=list)
    remediation_message: str = (
        "Query references a table that is not on the Terminus schema whitelist. "
        "The operation is blocked. Restrict the query to approved tables."
    )

    _table_patterns: list[str] = PrivateAttr(default_factory=list)
    _column_rules: list[WhitelistTable] = PrivateAttr(default_factory=list)
    _dialect: str = PrivateAttr(default="")

    @field_validator("tables", mode="before")
    @classmethod
    def _coerce_entries(cls, value: Any) -> list[Any]:
        coerced: list[Any] = []
        for entry in value or []:
            if isinstance(entry, (str, WhitelistTable)):
                coerced.append(entry)
            elif isinstance(entry, dict):
                if len(entry) != 1:
                    raise ValueError("a table entry object must have exactly one table-name key")
                name, body = next(iter(entry.items()))
                body = body or {}
                coerced.append({"name": name, "columns": body.get("columns")})
            else:
                raise ValueError("table entry must be a string or a single-key mapping")
        return coerced

    @model_validator(mode="after")
    def _build_views(self, info: ValidationInfo) -> SchemaWhitelist:
        """Derive the two lookup views from ``tables`` after validation.

        ``_table_patterns`` holds every entry name/glob for the table-level
        allow check; ``_column_rules`` holds only exact-name entries that carry a
        ``columns`` list (glob entries with columns are warned about and ignored,
        since one column list cannot sensibly apply across every matched table).
        """
        self._dialect = (info.context or {}).get("dialect", "") if info else ""
        patterns: list[str] = []
        rules: list[WhitelistTable] = []
        for entry in self.tables:
            name = entry if isinstance(entry, str) else entry.name
            patterns.append(name)
            if isinstance(entry, WhitelistTable) and entry.columns is not None:
                if _is_glob(name):
                    _log.warning("schema_whitelist_glob_columns_ignored", table=name)
                else:
                    rules.append(entry)
        self._table_patterns = patterns
        self._column_rules = rules
        return self

    def disallowed_tables(self, query_tables: list[str]) -> list[str]:
        """Return the referenced tables that are NOT on the whitelist.

        Config patterns are case-folded, but the query table is the parser's
        quote-aware canonical name and is matched case-sensitively: a quoted
        case-variant of a whitelisted table (`public.USERS`) is a distinct object
        and stays disallowed (F10b). Unquoted names are already lowercased by the
        parser, so they match as before.
        """
        patterns = [_normalize_config_pattern(p, self._dialect) for p in self._table_patterns]
        return [
            table
            for table in query_tables
            if not any(fnmatchcase(table, pattern) for pattern in patterns)
        ]

    def column_restrictions(self, query_tables: list[str]) -> dict[str, set[str]]:
        """For each referenced table with a column rule, the allowed column set."""
        result: dict[str, set[str]] = {}
        for table in query_tables:
            allowed: set[str] = set()
            matched = False
            for rule in self._column_rules:
                # Query table is the parser's quote-aware canonical name; the rule name
                # is case-folded config. A quoted case-variant won't match (F10b).
                if table == _normalize_config_identifier(rule.name, self._dialect):
                    matched = True
                    allowed |= {
                        _normalize_config_identifier(col, self._dialect)
                        for col in (rule.columns or [])
                    }
            if matched:
                result[table] = allowed
        return result


class ColumnViolation(BaseModel):
    """Structured detail of a column-allowlist denial, for remediation/audit."""

    kind: Literal["wildcard", "disallowed", "qualify", "insert_all"]
    table: str | None = None
    denied: list[str] = Field(default_factory=list)
    allowed: list[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    """Policy evaluation result consumed by the interceptor.

    ``reason`` is the human-readable explanation surfaced to the agent and audit
    log. ``reason_code`` is a stable, low-cardinality tag used only for metrics
    labels (so Prometheus time-series stay bounded).
    """

    action: PolicyAction
    policy_id: str | None = None
    policy_name: str | None = None
    reason: str
    reason_code: str = "unspecified"
    remediation_message: str | None = None
    column_violation: ColumnViolation | None = None


class PolicyEngine:
    """Evaluates parsed SQL against a loaded Terminus policy."""

    def __init__(
        self,
        config: PolicyConfig,
        whitelist: SchemaWhitelist | None = None,
        *,
        enforce_injection: bool = False,
    ) -> None:
        self._config = config
        self._whitelist = whitelist
        self._enforce_injection = enforce_injection
        self._rules = sorted(config.policies, key=lambda rule: rule.priority, reverse=True)

    @property
    def whitelist(self) -> SchemaWhitelist | None:
        """The active schema whitelist (read-only), for building a RoleResolver."""
        return self._whitelist

    @property
    def rule_count(self) -> int:
        """Number of policy rules (for observability)."""
        return len(self._rules)

    @classmethod
    def from_default_policy(cls) -> PolicyEngine:
        """Load the example policy and schema whitelist shipped with the repository."""

        project_root = Path(__file__).resolve().parents[3]
        dialect = get_settings().sql_dialect
        config = PolicyConfig.model_validate(
            _load_yaml(project_root / "examples" / "policy.yaml"), context={"dialect": dialect}
        )

        whitelist_path = project_root / "examples" / "schema_whitelist.yaml"
        whitelist = (
            SchemaWhitelist.model_validate(_load_yaml(whitelist_path), context={"dialect": dialect})
            if whitelist_path.exists()
            else None
        )
        return cls(config, whitelist=whitelist)

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        """Load a policy YAML file from disk (no schema whitelist)."""

        dialect = get_settings().sql_dialect
        return cls(PolicyConfig.model_validate(_load_yaml(path), context={"dialect": dialect}))

    def evaluate(self, parsed_sql: ParsedSQL, *, agent_id: str | None = None) -> PolicyDecision:
        """Evaluate parsed SQL and return an allow/deny/review decision.

        Invalid SQL is denied before rule matching. Otherwise, rules are checked in
        descending priority order. If no rule matches, the configured default action
        is applied, which should be ``deny`` for production policies.
        """

        if not parsed_sql.is_valid:
            # The parser tags why it failed via risk_reasons[0]; keep it to the
            # known low-cardinality set so an operator can alert on an oversize
            # (DoS-probe) flood separately from ordinary malformed SQL.
            code = parsed_sql.risk_reasons[0] if parsed_sql.risk_reasons else "invalid_sql"
            if code not in {"invalid_sql", "oversize_sql"}:
                code = "invalid_sql"
            reason = (
                "SQL exceeds the maximum accepted size."
                if code == "oversize_sql"
                else "SQL could not be parsed safely."
            )
            return PolicyDecision(
                action="deny",
                reason=reason,
                reason_code=code,
                remediation_message=self._config.default_remediation_message,
            )

        if parsed_sql.operation == "MULTI_STATEMENT":
            return PolicyDecision(
                action="deny",
                reason="Multiple SQL statements are blocked by default.",
                reason_code="multi_statement",
                remediation_message=self._config.default_remediation_message,
            )

        whitelist_decision = self._evaluate_whitelist(parsed_sql)
        if whitelist_decision is not None:
            return whitelist_decision

        column_decision = self._evaluate_columns(parsed_sql)
        if column_decision is not None:
            return column_decision

        injection_decision = self._evaluate_injection(parsed_sql)
        if injection_decision is not None:
            return injection_decision

        nested_write_decision = self._evaluate_nested_writes(parsed_sql)
        if nested_write_decision is not None:
            return nested_write_decision

        for rule in self._rules:
            if not self._matches(rule.match, parsed_sql, agent_id=agent_id):
                continue

            limit_decision = self._evaluate_limits(rule, parsed_sql)
            if limit_decision is not None:
                return limit_decision

            return PolicyDecision(
                action=rule.action,
                policy_id=rule.id,
                policy_name=rule.name,
                reason=f"Matched policy: {rule.name}",
                reason_code="policy_rule",
                remediation_message=self._remediation_message(rule),
            )

        return PolicyDecision(
            action=self._config.default_action,
            reason="No policy allowed this operation; default policy applied.",
            reason_code="default",
            remediation_message=self._config.default_remediation_message,
        )

    def suggest_rewrite(
        self,
        parsed_sql: ParsedSQL,
        sql: str,
        decision: PolicyDecision,
        *,
        agent_id: str | None = None,
        dialect: str | None = None,
        max_length: int = MAX_SQL_LENGTH,
    ) -> str | None:
        """Return a re-validated safe rewrite for a wildcard column denial, else None.

        Only fires for column-whitelist wildcard denials. The candidate rewrite is
        re-evaluated for the SAME agent and returned only if it would be allowed,
        so Terminus never hands back SQL that still violates policy. Never calls
        back into rewrite generation, so there is no recursion.
        """
        violation = decision.column_violation
        if (
            decision.reason_code != "column_whitelist"
            or violation is None
            or violation.kind != "wildcard"
            or self._whitelist is None
        ):
            return None

        try:
            restrictions = self._whitelist.column_restrictions(parsed_sql.tables)
            candidate = rewrite_wildcard(sql, restrictions, dialect=dialect)
            if candidate is None:
                return None
            verdict = self.evaluate(
                parse_sql(candidate, dialect=dialect, max_length=max_length), agent_id=agent_id
            )
            return candidate if verdict.action == "allow" else None
        except Exception as exc:  # fail safe: never attach a rewrite we could not verify
            _log.warning("suggest_rewrite_failed", error=exc.__class__.__name__)
            return None

    def _matches(
        self,
        match: PolicyMatch,
        parsed_sql: ParsedSQL,
        *,
        agent_id: str | None,
    ) -> bool:
        if match.operation is not None:
            operations = {operation.upper() for operation in match.operation}
            if parsed_sql.operation.upper() not in operations:
                return False

        if match.tables is not None and not _matches_any_table(
            parsed_sql.tables, match.tables, self._config._dialect
        ):
            return False

        if match.agent_ids is not None:
            normalized_agent_id = agent_id or ""
            if not any(fnmatchcase(normalized_agent_id, pattern) for pattern in match.agent_ids):
                return False

        if match.conditions is None or match.conditions.has_where is None:
            return True

        return parsed_sql.has_where is match.conditions.has_where

    def _evaluate_whitelist(self, parsed_sql: ParsedSQL) -> PolicyDecision | None:
        """Deny any query that references a table outside the schema whitelist."""
        if self._whitelist is None or not self._whitelist.enabled:
            return None

        disallowed = self._whitelist.disallowed_tables(parsed_sql.tables)
        if not disallowed:
            return None

        return PolicyDecision(
            action="deny",
            policy_id="schema_whitelist",
            reason=f"Table(s) not on schema whitelist: {', '.join(disallowed)}.",
            reason_code="schema_whitelist",
            remediation_message=self._whitelist.remediation_message,
        )

    def _evaluate_columns(self, parsed_sql: ParsedSQL) -> PolicyDecision | None:
        """Deny queries that reference columns outside a table's column allowlist."""
        if self._whitelist is None or not self._whitelist.enabled:
            return None
        restricted = self._whitelist.column_restrictions(parsed_sql.tables)
        if not restricted:
            return None

        # An INSERT with no explicit column list writes every column implicitly, so
        # on a column-restricted target it cannot be proven within the allowed set
        # (same reasoning as a bare `*`). Gate on the TARGET table specifically, so
        # `INSERT INTO <unrestricted> SELECT <allowed> FROM <restricted>` is not a
        # false positive. Covers a nested (writable-CTE) INSERT too.
        no_list_restricted = [t for t in parsed_sql.insert_all_tables if t in restricted]
        if no_list_restricted:
            table = no_list_restricted[0]
            return self._column_decision(
                ColumnViolation(kind="insert_all", table=table, allowed=sorted(restricted[table])),
                reason=f"INSERT without an explicit column list is not permitted on "
                f"column-restricted table {table}; list the specific columns to write.",
            )

        if parsed_sql.has_bare_star:
            tables = sorted(restricted)
            allowed = sorted({col for cols in restricted.values() for col in cols})
            return self._column_decision(
                ColumnViolation(kind="wildcard", table=", ".join(tables), allowed=allowed),
                reason=f"Wildcard '*' is not permitted on column-restricted table(s): "
                f"{', '.join(tables)}.",
            )

        for table in parsed_sql.star_tables:
            if table in restricted:
                return self._column_decision(
                    ColumnViolation(
                        kind="wildcard", table=table, allowed=sorted(restricted[table])
                    ),
                    reason=f"Wildcard '{table}.*' is not permitted on column-restricted "
                    f"table {table}.",
                )

        for column in parsed_sql.columns:
            if column.table is not None:
                if column.table in restricted and column.name not in restricted[column.table]:
                    return self._column_decision(
                        ColumnViolation(
                            kind="disallowed",
                            table=column.table,
                            denied=[column.name],
                            allowed=sorted(restricted[column.table]),
                        ),
                        reason=f"Column '{column.name}' is not allowed on table "
                        f"{column.table}.",
                    )
            else:
                _log.info(
                    "column_attribution_ambiguous",
                    column=column.name,
                    tables=sorted(restricted),
                )
                return self._column_decision(
                    ColumnViolation(kind="qualify", denied=[column.name]),
                    reason=f"Unqualified column '{column.name}' is ambiguous while a "
                    f"column-restricted table is in the query; qualify it as table.column.",
                )

        return None

    def _column_decision(self, violation: ColumnViolation, *, reason: str) -> PolicyDecision:
        message = self._whitelist.remediation_message if self._whitelist is not None else None
        return PolicyDecision(
            action="deny",
            policy_id="column_whitelist",
            reason=reason,
            reason_code="column_whitelist",
            remediation_message=message,
            column_violation=violation,
        )

    def _evaluate_injection(self, parsed_sql: ParsedSQL) -> PolicyDecision | None:
        """Deny a query that calls an injection/time-based SQL function.

        Fail-closed allow-path gate: it runs after the whitelist/column checks and
        before the rule loop, so it can only escalate an otherwise-allow to a deny,
        never downgrade a deny. Keyed on the AST-derived ``has_injection_function``
        flag (never substrings), so a type name like ``varchar(255)`` is unaffected.
        Off by default at the engine level; the app enables it via
        ``TERMINUS_ENFORCE_INJECTION_BLOCK`` (default true). When off, the signal is
        still surfaced in ``risk_reasons``/metrics but never changes the decision.
        """
        if not self._enforce_injection or not parsed_sql.security_flags.has_injection_function:
            return None
        return PolicyDecision(
            action="deny",
            policy_id="injection_function",
            reason="Query calls a disallowed injection or time-based SQL function.",
            reason_code="injection_function",
            remediation_message=self._config.default_remediation_message,
        )

    def _evaluate_nested_writes(self, parsed_sql: ParsedSQL) -> PolicyDecision | None:
        """Deny a statement that hides a data-modifying operation inside a CTE.

        Fail-closed structural gate. A write nested in a writable CTE is
        classified by the top-level ``operation`` only, so the operation-based
        rules below never see it (e.g. a DELETE hidden under a top-level SELECT).
        This runs after the whitelist/column/injection gates, so their more
        specific reason codes win when they also apply, and before the rule loop,
        so it can only escalate an otherwise-allow to a deny, never downgrade a
        deny. The parser detects nested writes by CTE body, so a top-level MERGE
        is not misflagged. Unlike injection, this gate is not operator-toggleable:
        a smuggled write has no benign reading under a default-deny posture.
        """
        if not parsed_sql.nested_write_operations:
            return None
        ops = ", ".join(parsed_sql.nested_write_operations)
        return PolicyDecision(
            action="deny",
            policy_id="nested_write",
            reason=(
                f"A data-modifying operation ({ops}) nested in a CTE is not permitted; "
                "submit the write as a top-level statement so policy can evaluate it."
            ),
            reason_code="nested_write",
            remediation_message=self._config.default_remediation_message,
        )

    def _evaluate_limits(self, rule: PolicyRule, parsed_sql: ParsedSQL) -> PolicyDecision | None:
        if rule.limits is None or rule.limits.max_destructive_risk_score is None:
            return None

        if parsed_sql.risk_score <= rule.limits.max_destructive_risk_score:
            return None

        return PolicyDecision(
            action="deny",
            policy_id=rule.id,
            policy_name=rule.name,
            reason="Policy risk threshold exceeded.",
            reason_code="risk_threshold",
            remediation_message=self._remediation_message(rule),
        )

    def _remediation_message(self, rule: PolicyRule) -> str | None:
        if rule.remediation is None:
            return None
        return rule.remediation.message


def _load_yaml(path: str | Path) -> dict[str, object]:
    """Read a YAML file into a dict (empty file -> empty dict)."""
    with Path(path).open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    return dict(loaded)


def _matches_any_table(query_tables: list[str], policy_patterns: list[str], dialect: str) -> bool:
    if not query_tables:
        return False

    normalized_patterns = [_normalize_config_pattern(p, dialect) for p in policy_patterns]
    return any(
        # Query table is the parser's quote-aware canonical name (unquoted already
        # lowercased, quoted preserved); patterns are case-folded config (F10b).
        fnmatchcase(query_table, pattern)
        for query_table in query_tables
        for pattern in normalized_patterns
    )


def get_policy_engine() -> PolicyEngine:
    """Return the current policy engine from the governance snapshot."""
    # Deferred import avoids a cycle (governance imports this module).
    from terminus.config.governance import get_governance_manager

    return get_governance_manager().snapshot.engine
