from datetime import timedelta

import jwt as _jwt
import pytest
from fastapi.testclient import TestClient

from terminus.audit.audit_logger import AuditLogger
from terminus.auth.__main__ import main as auth_cli_main
from terminus.auth.registry import AgentRegistry
from terminus.auth.tokens import AuthResult, mint_token, verify_token
from terminus.config.settings import TerminusSettings
from terminus.main import app
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import (
    ColumnViolation,
    PolicyDecision,
    PolicyEngine,
    SchemaWhitelist,
)
from terminus.remediation.remediation import build_remediation
from terminus.rewrite import rewrite_wildcard


def test_settings_honor_uppercase_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Conventional UPPERCASE TERMINUS_* env vars (used by Docker) must be read.

    Regression guard: with case-sensitive settings the docker-compose env vars,
    including the audit HMAC signing key, were silently ignored.
    """
    monkeypatch.setenv("TERMINUS_RATE_LIMIT_PER_MINUTE", "42")
    monkeypatch.setenv("TERMINUS_AUDIT_HMAC_KEY", "x" * 40)

    settings = TerminusSettings()

    assert settings.rate_limit_per_minute == 42
    assert settings.audit_hmac_key == "x" * 40


def test_health_endpoint_reports_ok() -> None:
    """Health endpoint must return 200 with status, service, and environment."""
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "terminus"
    assert "environment" in data
    assert data["environment"] in ("development", "staging", "production")


def test_parser_extracts_update_without_where_as_high_risk() -> None:
    result = parse_sql("UPDATE public.users SET name = 'redacted'")

    assert result.operation == "UPDATE"
    assert result.tables == ["public.users"]
    assert result.has_where is False
    assert result.risk_score >= 0.7


# --- F4: bound parse cost + fail-closed parser (never block the loop, never 500) ---


def test_parse_sql_rejects_unknown_dialect_without_raising() -> None:
    p = parse_sql("SELECT id FROM public.users", dialect="bogus")
    assert p.is_valid is False
    assert p.risk_reasons == ["invalid_sql"]


def test_parse_sql_survives_deep_nesting_without_raising() -> None:
    p = parse_sql("SELECT " + "(" * 5000 + "1" + ")" * 5000, dialect="postgres")
    assert p.is_valid is False


def test_parse_sql_rejects_oversize_before_parsing() -> None:
    p = parse_sql("SELECT " + "1," * 20000 + "1", max_length=16_384)
    assert p.is_valid is False
    assert p.risk_reasons == ["oversize_sql"]


def test_parse_sql_catches_unexpected_parser_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import terminus.parser.sql_parser as parser_mod

    def _boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("unexpected sqlglot failure")

    monkeypatch.setattr(parser_mod.sqlglot, "parse", _boom)
    p = parse_sql("SELECT id FROM public.users", dialect="postgres")
    assert p.is_valid is False
    assert p.risk_reasons == ["invalid_sql"]


def test_parse_sql_large_but_legit_query_under_cap_parses() -> None:
    sql = "SELECT id FROM public.users WHERE id IN (" + ",".join(str(i) for i in range(2000)) + ")"
    assert len(sql) < 16_384
    p = parse_sql(sql, dialect="postgres")
    assert p.is_valid is True
    assert p.operation == "SELECT"


def test_engine_oversize_denies_with_distinct_reason_code() -> None:
    engine = PolicyEngine.from_default_policy()
    p = parse_sql("SELECT " + "1," * 20000 + "1", max_length=16_384)
    decision = engine.evaluate(p, agent_id="analytics_agent_42")
    assert decision.action == "deny"
    assert decision.reason_code == "oversize_sql"


def test_engine_bad_dialect_denies_with_invalid_sql_reason_code() -> None:
    engine = PolicyEngine.from_default_policy()
    decision = engine.evaluate(
        parse_sql("SELECT id FROM public.users", dialect="bogus"),
        agent_id="analytics_agent_42",
    )
    assert decision.action == "deny"
    assert decision.reason_code == "invalid_sql"


def test_intercept_bad_dialect_denies_not_500() -> None:
    client = TestClient(app)
    r = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users", "dialect": "bogus", "agent_id": "a"},
    )
    assert r.status_code == 403
    assert r.json()["decision"] == "deny"


def test_intercept_deep_nesting_denies_not_500() -> None:
    client = TestClient(app)
    r = client.post(
        "/intercept",
        json={"sql": "SELECT " + "(" * 5000 + "1" + ")" * 5000, "agent_id": "a"},
    )
    assert r.status_code == 403
    assert r.json()["decision"] == "deny"


def test_intercept_oversize_sql_denies_not_500() -> None:
    client = TestClient(app)
    big = "SELECT id FROM public.users WHERE id IN (" + ",".join("1" for _ in range(20000)) + ")"
    r = client.post("/intercept", json={"sql": big, "agent_id": "a"})
    assert r.status_code == 403
    assert r.json()["decision"] == "deny"


def test_intercept_body_over_field_cap_rejected_422() -> None:
    client = TestClient(app)
    r = client.post("/intercept", json={"sql": "x" * 131_073, "agent_id": "a"})
    assert r.status_code == 422


def test_intercept_oversized_request_body_rejected_413() -> None:
    # A large body (here via unbounded metadata) is rejected BEFORE JSON parsing,
    # so it cannot burn memory in the request path. F4 review follow-up.
    client = TestClient(app)
    huge = '{"sql":"SELECT 1","agent_id":"a","metadata":{"x":"' + "y" * 300_000 + '"}}'
    r = client.post(
        "/intercept", content=huge.encode(), headers={"content-type": "application/json"}
    )
    assert r.status_code == 413


def test_suggest_rewrite_respects_max_length() -> None:
    # The wildcard-rewrite revalidation reparse must honor the configured cap, so
    # a rewrite that would exceed it is not offered (F4 review follow-up).
    engine = _engine_with_users_columns()  # public.users restricted to [id, name]
    parsed = parse_sql("SELECT * FROM public.users")
    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")
    assert decision.reason_code == "column_whitelist"
    assert (
        engine.suggest_rewrite(
            parsed, "SELECT * FROM public.users", decision, agent_id="analytics_agent_42"
        )
        is not None
    )
    assert (
        engine.suggest_rewrite(
            parsed,
            "SELECT * FROM public.users",
            decision,
            agent_id="analytics_agent_42",
            max_length=1,
        )
        is None
    )


def test_policy_allows_approved_analytics_read() -> None:
    engine = PolicyEngine.from_default_policy()
    parsed = parse_sql("SELECT id FROM public.users WHERE id = 1")

    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")

    assert decision.action == "allow"
    assert decision.policy_id == "allow_analytics_reads"


def test_policy_denies_update_without_required_where_clause() -> None:
    engine = PolicyEngine.from_default_policy()
    parsed = parse_sql("UPDATE public.users SET name = 'redacted'")

    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")

    assert decision.action == "deny"
    assert decision.policy_id is None
    assert "blocked" in decision.reason.lower() or "no policy" in decision.reason.lower()


def test_intercept_denies_destructive_sql_with_remediation_header() -> None:
    client = TestClient(app)

    response = client.post(
        "/intercept",
        json={"sql": "DROP TABLE public.users", "agent_id": "analytics_agent_42"},
    )

    assert response.status_code == 403
    payload = response.json()
    assert payload["decision"] == "deny"
    assert payload["operation"] == "DROP"
    assert payload["remediation"]
    assert response.headers["X-Terminus-Remediation"]
    assert "DROP TABLE public.users" not in response.text


def test_intercept_allows_approved_select() -> None:
    client = TestClient(app)

    response = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users", "agent_id": "analytics_agent_42"},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"


def test_policy_denies_table_not_on_schema_whitelist() -> None:
    """A query touching a non-whitelisted table is denied before rule evaluation."""
    engine = PolicyEngine.from_default_policy()
    parsed = parse_sql("SELECT id FROM secret.credentials")

    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")

    assert decision.action == "deny"
    assert decision.reason_code == "schema_whitelist"
    assert decision.policy_id == "schema_whitelist"


def test_policy_whitelist_allows_approved_table() -> None:
    """A whitelisted table still flows through to the normal allow rules."""
    engine = PolicyEngine.from_default_policy()
    parsed = parse_sql("SELECT id FROM public.users WHERE id = 1")

    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")

    assert decision.action == "allow"
    assert decision.policy_id == "allow_analytics_reads"


def test_schema_whitelist_glob_matching() -> None:
    """Whitelist config patterns are case-folded, but a parser-canonical query name
    is matched case-sensitively: a quoted case-variant is a distinct object (F10b)."""
    whitelist = SchemaWhitelist(tables=["public.users", "analytics.*"])

    assert whitelist.disallowed_tables(["public.users"]) == []
    assert whitelist.disallowed_tables(["analytics.daily_revenue"]) == []
    # A canonical name differing in case is only ever produced by a QUOTED case-variant
    # (the parser lowercases unquoted names), so it is a distinct, non-whitelisted object.
    assert whitelist.disallowed_tables(["PUBLIC.USERS"]) == ["PUBLIC.USERS"]
    # Under a schema glob, any table in the case-exact whitelisted schema still matches.
    assert whitelist.disallowed_tables(["analytics.DAILY"]) == []
    # A case-variant of the schema itself is a distinct, non-whitelisted schema.
    assert whitelist.disallowed_tables(["ANALYTICS.daily"]) == ["ANALYTICS.daily"]
    assert whitelist.disallowed_tables(["hr.salaries"]) == ["hr.salaries"]


# ---------------------------------------------------------------------------
# F10b: quote-aware TABLE identifier matching. A QUOTED table identifier is
# case-sensitive in standard SQL / Postgres, so `"public"."USERS"` is a distinct
# table from the whitelisted `public.users` and must NOT be folded onto it.
# Unquoted table names still fold to lowercase. Fail-closed: a quoted case-variant
# of a whitelisted table stops matching and is denied at the schema-whitelist gate.
# ---------------------------------------------------------------------------


def test_tables_deny_quoted_case_variant_of_whitelisted_table() -> None:
    decision = _decide('SELECT id FROM "public"."USERS" WHERE id = 1')
    assert decision.action == "deny"
    assert decision.reason_code == "schema_whitelist"


def test_tables_deny_quoted_case_variant_schema_and_table() -> None:
    decision = _decide('SELECT id FROM "PUBLIC"."USERS" WHERE id = 1')
    assert decision.action == "deny"
    assert decision.reason_code == "schema_whitelist"


def test_tables_allow_unquoted_mixed_case_table_folds() -> None:
    # Unquoted table names fold to lowercase, so PUBLIC.USERS resolves to public.users.
    assert _decide("SELECT id FROM PUBLIC.USERS WHERE id = 1").action == "allow"


def test_tables_allow_quoted_lowercase_table_exact() -> None:
    assert _decide('SELECT id FROM "public"."users" WHERE id = 1').action == "allow"


def test_tables_allow_mixed_quoted_schema_unquoted_table() -> None:
    assert _decide('SELECT id FROM "public".users WHERE id = 1').action == "allow"


def test_tables_quoted_lowercase_table_column_restriction_still_applies() -> None:
    # Attribution intact: a quoted-lowercase whitelisted+restricted table still enforces
    # its column allowlist (password_hash is not on the {id, name} allowlist).
    decision = _decide('SELECT "public"."users"."password_hash" FROM "public"."users"')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_tables_quoted_case_variant_qualified_star_denies_at_table() -> None:
    decision = _decide('SELECT "public"."USERS".* FROM "public"."USERS"')
    assert decision.action == "deny"
    assert decision.reason_code == "schema_whitelist"


def test_tables_quoted_lowercase_aliases_in_join_resolve() -> None:
    # Multi-table (so single-table fallback does NOT apply): quoted-lowercase tables and
    # quoted aliases must resolve, else the restricted public.users forces a fail-closed
    # deny. All columns attribute to allowed positions -> allow.
    decision = _decide(
        'SELECT "u"."name" FROM "public"."users" "u" '
        'JOIN "public"."orders" "o" ON "u"."id" = "o"."user_id"'
    )
    assert decision.action == "allow"


def test_disabled_schema_whitelist_is_skipped() -> None:
    """When the whitelist is disabled it must not deny anything."""
    whitelist = SchemaWhitelist(enabled=False, tables=["public.users"])
    engine = PolicyEngine.from_default_policy()
    engine._whitelist = whitelist  # exercise the disabled branch directly

    parsed = parse_sql("SELECT id FROM hr.salaries")
    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")

    # Not denied by the whitelist; falls through to the default policy instead.
    assert decision.reason_code != "schema_whitelist"


def _cols(sql: str) -> set[tuple[str, str | None]]:
    return {(c.name, c.table) for c in parse_sql(sql).columns}


def test_parser_attributes_unqualified_columns_single_table() -> None:
    assert _cols("SELECT id, name FROM public.users") == {
        ("id", "public.users"),
        ("name", "public.users"),
    }


def test_parser_resolves_alias_qualified_columns() -> None:
    cols = _cols("SELECT u.name FROM public.users u JOIN public.orders o ON u.id = o.user_id")
    assert ("name", "public.users") in cols
    assert ("user_id", "public.orders") in cols


def test_parser_resolves_schema_qualified_columns() -> None:
    assert ("id", "public.users") in _cols("SELECT public.users.id FROM public.users")


def test_parser_unqualified_column_in_join_is_ambiguous() -> None:
    cols = _cols("SELECT name FROM public.users u JOIN public.orders o ON u.id = o.user_id")
    assert ("name", None) in cols


def test_parser_excludes_select_output_aliases() -> None:
    # `user_id` in ORDER BY references the output alias, not a real column.
    cols = _cols("SELECT id AS user_id FROM public.users ORDER BY user_id")
    assert ("id", "public.users") in cols
    assert all(name != "user_id" for name, _ in cols)


def test_parser_detects_bare_and_qualified_wildcards() -> None:
    assert parse_sql("SELECT * FROM public.users").has_bare_star is True
    starred = parse_sql("SELECT u.* FROM public.users u")
    assert starred.has_bare_star is False
    assert starred.star_tables == ["public.users"]


def test_parser_flags_injection_function_via_ast() -> None:
    """Injection / time-based function calls are flagged by AST node name."""
    assert (
        parse_sql(
            "SELECT id FROM public.users WHERE id = 1 AND pg_sleep(10) IS NULL"
        ).security_flags.has_injection_function
        is True
    )
    assert (
        parse_sql(
            "SELECT id FROM public.orders WHERE amount > benchmark(1000000, md5('x'))",
            dialect="mysql",
        ).security_flags.has_injection_function
        is True
    )


def test_parser_does_not_flag_type_names_as_injection() -> None:
    """AST detection: varchar(255)/nchar(10) are DataTypes and char_length/to_char are
    ordinary functions, so none set the injection flag or inflate risk. This is the fix
    for the substring 'char(' false positive."""
    for q in (
        "SELECT CAST(id AS varchar(255)) FROM public.orders WHERE id = 1",
        "SELECT CAST(id AS nchar(10)) FROM public.orders WHERE id = 1",
        "SELECT char_length(name) FROM public.orders WHERE id = 1",
        "SELECT to_char(created_at, 'YYYY') FROM public.orders WHERE id = 1",
    ):
        flags = parse_sql(q).security_flags
        assert flags.has_injection_function is False, q
        assert flags.has_smuggling_pattern is False, q


def test_parser_flags_qualified_and_quoted_injection_functions() -> None:
    """Quoting or schema-qualifying a dangerous function must not evade detection.

    Regression guard: `"pg_sleep"(10)` previously slipped through because the name
    was read with its quote characters attached.
    """
    for q in (
        'SELECT id FROM public.users WHERE id = 1 AND "pg_sleep"(10) IS NULL',
        "SELECT id FROM public.users WHERE id = 1 AND pg_catalog.pg_sleep(10) IS NULL",
        "SELECT id FROM public.users WHERE id = 1 AND PG_SLEEP(10) IS NULL",
    ):
        assert parse_sql(q, dialect="postgres").security_flags.has_injection_function is True, q


def test_injection_gate_denies_quoted_injection_function() -> None:
    d = _decide_enforced('SELECT id FROM public.orders WHERE id = 1 AND "pg_sleep"(10) IS NULL')
    assert d.action == "deny"
    assert d.reason_code == "injection_function"


def test_command_form_dangerous_statements_still_deny() -> None:
    """WAITFOR / EXEC statement forms are not function calls (so not the
    injection_function gate), but they are still denied by the invalid-SQL,
    whitelist, and default-deny gates. Containment guard for the command-form
    variants of the denylist."""
    base = PolicyEngine.from_default_policy()
    engine = PolicyEngine(base._config, whitelist=base._whitelist, enforce_injection=True)
    for q, dialect in (
        ("WAITFOR DELAY '00:00:05'", "tsql"),
        ("EXEC xp_cmdshell 'whoami'", "tsql"),
        ("SELECT id FROM public.users WHERE id = 1; WAITFOR DELAY '00:00:05'", "tsql"),
    ):
        decision = engine.evaluate(parse_sql(q, dialect=dialect), agent_id="analytics_agent_42")
        assert decision.action == "deny", q


def test_parser_ignores_aggregate_star() -> None:
    parsed = parse_sql("SELECT COUNT(*) FROM public.users")
    assert parsed.has_bare_star is False
    assert parsed.star_tables == []


def test_parser_self_join_attributes_to_single_table() -> None:
    cols = _cols("SELECT name FROM public.users u1 JOIN public.users u2 ON u1.id = u2.id")
    # deduped table set is one table -> unqualified `name` attributes to it.
    assert ("name", "public.users") in cols


def test_risk_reasons_destructive_drop() -> None:
    assert "destructive_operation" in parse_sql("DROP TABLE public.users").risk_reasons


def test_risk_reasons_update_without_where() -> None:
    reasons = parse_sql("UPDATE public.users SET name = 'x'").risk_reasons
    assert "no_where_clause" in reasons


def test_risk_reasons_wildcard_select() -> None:
    assert "wildcard_select" in parse_sql("SELECT * FROM public.users").risk_reasons


def test_risk_reasons_clean_select_is_empty() -> None:
    assert parse_sql("SELECT id FROM public.users WHERE id = 1").risk_reasons == []


def test_risk_reasons_invalid_sql() -> None:
    assert parse_sql("SELECT FROM WHERE )(").risk_reasons == ["invalid_sql"]


def test_risk_reasons_multi_statement() -> None:
    parsed = parse_sql("SELECT 1; SELECT 2")
    assert parsed.operation == "MULTI_STATEMENT"
    assert parsed.risk_reasons == ["multi_statement"]


def test_risk_reasons_security_flags_on_main_path() -> None:
    # A UNION is a hidden set-operation: the parser flags it and that surfaces
    # as structured reasons on the normal (single-statement) scoring path.
    reasons = parse_sql("SELECT a FROM t1 UNION SELECT b FROM t2").risk_reasons
    assert "hidden_subquery" in reasons
    assert "smuggling_pattern" in reasons


def test_whitelist_accepts_object_table_entry() -> None:
    wl = SchemaWhitelist.model_validate(
        {"tables": [{"public.users": {"columns": ["id", "name"]}}, "public.orders"]}
    )
    assert wl.disallowed_tables(["public.users", "public.orders"]) == []
    assert wl.column_restrictions(["public.users"]) == {"public.users": {"id", "name"}}
    assert wl.column_restrictions(["public.orders"]) == {}


def test_whitelist_string_entries_have_no_column_restriction() -> None:
    wl = SchemaWhitelist(tables=["public.users"])
    assert wl.column_restrictions(["public.users"]) == {}


def test_whitelist_glob_with_columns_is_ignored() -> None:
    wl = SchemaWhitelist.model_validate({"tables": [{"analytics.*": {"columns": ["only_this"]}}]})
    # Globs are always all-columns: the column list is dropped.
    assert wl.column_restrictions(["analytics.daily"]) == {}


def test_whitelist_column_match_is_case_insensitive() -> None:
    wl = SchemaWhitelist.model_validate({"tables": [{"public.users": {"columns": ["ID", "Name"]}}]})
    assert wl.column_restrictions(["public.users"]) == {"public.users": {"id", "name"}}


def _engine_with_users_columns() -> PolicyEngine:
    engine = PolicyEngine.from_default_policy()
    engine._whitelist = SchemaWhitelist.model_validate(
        {
            "enabled": True,
            "tables": [{"public.users": {"columns": ["id", "name"]}}, "public.orders"],
        }
    )
    return engine


def _decide(sql: str) -> "PolicyDecision":
    engine = _engine_with_users_columns()
    return engine.evaluate(parse_sql(sql), agent_id="analytics_agent_42")


def _decide_enforced(sql: str, dialect: str | None = None) -> "PolicyDecision":
    """Evaluate through an engine with injection enforcement ON (the prod default)."""
    base = PolicyEngine.from_default_policy()
    engine = PolicyEngine(base._config, whitelist=base._whitelist, enforce_injection=True)
    return engine.evaluate(parse_sql(sql, dialect=dialect), agent_id="analytics_agent_42")


def test_injection_gate_denies_injection_function_on_approved_table() -> None:
    d = _decide_enforced("SELECT id FROM public.orders WHERE id = 1 AND pg_sleep(10) IS NULL")
    assert d.action == "deny"
    assert d.reason_code == "injection_function"


def test_injection_gate_allows_benign_cast_when_enforced() -> None:
    # False-positive guard: a varchar cast must not be denied even with enforcement on.
    assert (
        _decide_enforced("SELECT CAST(id AS varchar(255)) FROM public.orders WHERE id = 1").action
        == "allow"
    )


def test_injection_signal_is_observe_only_when_disabled() -> None:
    # Enforcement OFF (the default engine): the decision is unchanged (advisory only).
    base = PolicyEngine.from_default_policy()
    d = base.evaluate(
        parse_sql("SELECT id FROM public.orders WHERE id = 1 AND pg_sleep(10) IS NULL"),
        agent_id="analytics_agent_42",
    )
    assert d.action == "allow"


def test_columns_allow_listed() -> None:
    assert _decide("SELECT id, name FROM public.users WHERE id = 1").action == "allow"


def test_columns_deny_disallowed_column() -> None:
    decision = _decide("SELECT password_hash FROM public.users")
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"
    assert decision.column_violation is not None
    assert decision.column_violation.kind == "disallowed"
    assert "password_hash" in decision.column_violation.denied


# --- F6: enforce the column allowlist on INSERT target columns ---


def test_parser_extracts_insert_target_columns() -> None:
    p = parse_sql("INSERT INTO public.users (id, name, ssn) VALUES (1, 2, 3)")
    assert ("ssn", "public.users") in {(c.name, c.table) for c in p.columns}
    assert p.insert_all_tables == []
    q = parse_sql("INSERT INTO public.users VALUES (1)")
    assert q.insert_all_tables == ["public.users"]


def test_columns_deny_insert_restricted_column_inside_cte() -> None:
    # A writable CTE must not smuggle a restricted-column INSERT past the gate.
    d = _decide(
        "WITH w AS (INSERT INTO public.users (id, ssn) VALUES (1, 'x') RETURNING id) SELECT 1"
    )
    assert d.action == "deny"
    assert d.reason_code == "column_whitelist"


def test_columns_deny_no_column_list_insert_inside_cte() -> None:
    d = _decide("WITH w AS (INSERT INTO public.users VALUES (1, 'a', 'b') RETURNING id) SELECT 1")
    assert d.action == "deny"
    assert d.column_violation is not None and d.column_violation.kind == "insert_all"


def test_columns_deny_insert_to_restricted_column() -> None:
    d = _decide("INSERT INTO public.users (id, name, ssn) VALUES (1, 'a', 'x')")
    assert d.action == "deny"
    assert d.reason_code == "column_whitelist"
    assert d.column_violation is not None and d.column_violation.kind == "disallowed"
    assert "ssn" in d.column_violation.denied


def test_columns_deny_insert_without_column_list_on_restricted_table() -> None:
    d = _decide("INSERT INTO public.users VALUES (1, 'a')")
    assert d.action == "deny"
    assert d.reason_code == "column_whitelist"
    assert d.column_violation is not None and d.column_violation.kind == "insert_all"


def test_columns_deny_insert_default_values_on_restricted_table() -> None:
    d = _decide("INSERT INTO public.users DEFAULT VALUES")
    assert d.action == "deny"
    assert d.column_violation is not None and d.column_violation.kind == "insert_all"


def test_columns_deny_insert_select_writes_restricted_column() -> None:
    d = _decide("INSERT INTO public.users (id, ssn) SELECT o.id, o.total FROM public.orders o")
    assert d.action == "deny"
    assert d.reason_code == "column_whitelist"


def test_columns_deny_insert_on_conflict_set_restricted_column() -> None:
    d = _decide(
        "INSERT INTO public.users (id) VALUES (1) "
        "ON CONFLICT (id) DO UPDATE SET password_hash = 'x'"
    )
    assert d.action == "deny"
    assert d.reason_code == "column_whitelist"


def test_columns_insert_to_unrestricted_table_not_a_column_violation() -> None:
    # public.orders has no column allowlist; a no-list INSERT is not a column violation.
    assert _decide("INSERT INTO public.orders VALUES (1, 2)").reason_code != "column_whitelist"


def test_insert_allowed_columns_pass_with_insert_policy() -> None:
    from terminus.policy.policy_engine import PolicyConfig

    cfg = PolicyConfig.model_validate(
        {
            "version": "1.0",
            "default_action": "deny",
            "policies": [
                {
                    "id": "ins",
                    "name": "ins",
                    "priority": 50,
                    "match": {"operation": ["INSERT"], "tables": ["public.users"]},
                    "action": "allow",
                }
            ],
        }
    )
    wl = SchemaWhitelist.model_validate(
        {"enabled": True, "tables": [{"public.users": {"columns": ["id", "name"]}}]}
    )
    engine = PolicyEngine(cfg, whitelist=wl)
    assert (
        engine.evaluate(
            parse_sql("INSERT INTO public.users (id, name) VALUES (1, 'a')"), agent_id="a"
        ).action
        == "allow"
    )
    assert (
        engine.evaluate(
            parse_sql("INSERT INTO public.users (id, ssn) VALUES (1, 'x')"), agent_id="a"
        ).action
        == "deny"
    )


def test_columns_deny_bare_star() -> None:
    decision = _decide("SELECT * FROM public.users")
    assert decision.action == "deny"
    assert decision.column_violation is not None
    assert decision.column_violation.kind == "wildcard"


def test_columns_deny_qualified_star() -> None:
    decision = _decide("SELECT u.* FROM public.users u")
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"
    assert decision.policy_id == "column_whitelist"
    assert decision.column_violation is not None
    assert decision.column_violation.kind == "wildcard"


def test_columns_allow_qualified_join_column() -> None:
    sql = "SELECT u.name FROM public.users u JOIN public.orders o ON u.id = o.user_id"
    assert _decide(sql).action == "allow"


def test_columns_deny_qualified_disallowed_join_column() -> None:
    sql = "SELECT u.password_hash FROM public.users u JOIN public.orders o ON u.id = o.user_id"
    decision = _decide(sql)
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"
    assert decision.column_violation is not None
    assert decision.column_violation.kind == "disallowed"


def test_columns_deny_ambiguous_join_column() -> None:
    sql = "SELECT name FROM public.users u JOIN public.orders o ON u.id = o.user_id"
    decision = _decide(sql)
    assert decision.action == "deny"
    assert decision.column_violation is not None
    assert decision.column_violation.kind == "qualify"


def test_columns_deny_update_to_restricted_column() -> None:
    decision = _decide("UPDATE public.users SET password_hash = 'x' WHERE id = 1")
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"
    assert decision.column_violation is not None
    assert decision.column_violation.kind == "disallowed"


def test_columns_allow_count_star_on_restricted_table() -> None:
    assert _decide("SELECT COUNT(*) FROM public.users WHERE id = 1").action == "allow"


def test_columns_unrestricted_table_unaffected() -> None:
    assert _decide("SELECT * FROM public.orders").action == "allow"


def test_columns_star_on_unrestricted_table_in_mixed_query_allowed() -> None:
    # public.orders is unrestricted; o.* must be allowed even though public.users is restricted.
    # u.id and o.user_id appear only in the ON clause and both resolve to allowed columns.
    sql = "SELECT o.* FROM public.orders o JOIN public.users u ON u.id = o.user_id"
    assert _decide(sql).action == "allow"


def test_columns_disabled_whitelist_skips_column_checks() -> None:
    engine = PolicyEngine.from_default_policy()
    engine._whitelist = SchemaWhitelist.model_validate(
        {"enabled": False, "tables": [{"public.users": {"columns": ["id"]}}]}
    )
    decision = engine.evaluate(parse_sql("SELECT password_hash FROM public.users"), agent_id="x")
    assert decision.reason_code != "column_whitelist"


def test_audit_event_includes_reasons() -> None:
    parsed = parse_sql("DROP TABLE public.users")
    engine = PolicyEngine.from_default_policy()
    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")
    event = AuditLogger._build_event(
        request_id="r1",
        agent_id="analytics_agent_42",
        parsed_sql=parsed,
        decision=decision,
        remediation_present=True,
        metadata={},
        sql="DROP TABLE public.users",
        key=TerminusSettings().audit_hmac_key,
    )
    assert event["reason"] == decision.reason
    assert event["reason_code"] == decision.reason_code
    assert event["risk_reasons"] == parsed.risk_reasons
    assert "DROP TABLE" not in str(event)  # raw SQL never logged


def test_remediation_names_disallowed_and_allowed_columns() -> None:
    decision = PolicyDecision(
        action="deny",
        reason="Column 'password_hash' is not allowed on table public.users.",
        reason_code="column_whitelist",
        column_violation=ColumnViolation(
            kind="disallowed",
            table="public.users",
            denied=["password_hash"],
            allowed=["id", "name"],
        ),
    )
    parsed = parse_sql("SELECT password_hash FROM public.users")
    remediation = build_remediation(decision, parsed)
    assert remediation is not None
    text = " ".join(remediation.suggestions).lower()
    assert "password_hash" in text
    assert "id" in text and "name" in text


def test_remediation_qualify_suggestion() -> None:
    decision = PolicyDecision(
        action="deny",
        reason="ambiguous",
        reason_code="column_whitelist",
        column_violation=ColumnViolation(kind="qualify", denied=["name"]),
    )
    parsed = parse_sql("SELECT name FROM public.users u JOIN public.orders o ON u.id = o.user_id")
    remediation = build_remediation(decision, parsed)
    assert remediation is not None
    assert any("qualif" in s.lower() for s in remediation.suggestions)


def test_remediation_wildcard_names_allowed_columns() -> None:
    decision = PolicyDecision(
        action="deny",
        reason="wildcard",
        reason_code="column_whitelist",
        column_violation=ColumnViolation(
            kind="wildcard", table="public.users", allowed=["id", "name"]
        ),
    )
    remediation = build_remediation(decision, parse_sql("SELECT * FROM public.users"))
    assert remediation is not None
    text = " ".join(remediation.suggestions).lower()
    assert "id" in text and "name" in text
    assert "public.users" in text


# ---------------------------------------------------------------------------
# Fail-open regression tests: alias/USING-key collision must not drop real
# selected columns from the extracted set.
# ---------------------------------------------------------------------------


def test_columns_deny_alias_collides_with_restricted_column() -> None:
    """Aliasing id AS password_hash must NOT cause the real password_hash projection to be dropped.

    Before the fix the alias 'password_hash' landed in `excluded`, which caused
    the bare `password_hash` column reference to be silently skipped, letting the
    query pass the column allowlist check even though it selected a restricted column.
    """
    decision = _decide("SELECT id AS password_hash, password_hash FROM public.users")
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_alias_collides_with_disallowed_column() -> None:
    """Same pattern: aliasing name AS email must not hide the real email projection."""
    assert _decide("SELECT name AS email, email FROM public.users").action == "deny"


def test_columns_deny_using_key_collides_with_restricted_column() -> None:
    """A USING join key must not suppress a projected column with the same name."""
    sql = "SELECT password_hash FROM public.users JOIN public.orders USING (password_hash)"
    assert _decide(sql).action == "deny"


def test_parser_does_not_drop_real_projection_colliding_with_alias() -> None:
    """The real bare `password_hash` projection must be extracted, not silently dropped.

    This is the parser-level attribution-lock that the engine tests depend on.
    """
    assert ("password_hash", "public.users") in _cols(
        "SELECT id AS password_hash, password_hash FROM public.users"
    )


def test_parser_keeps_restricted_column_shadowed_by_alias_in_where() -> None:
    """A WHERE reference to a column that shares a SELECT alias name is a real
    base-table column (SQL aliases are not visible in WHERE), so it must be
    extracted, not dropped. Regression guard for the alias-shadow column
    allowlist bypass.
    """
    cols = _cols("SELECT id AS ssn FROM public.users WHERE ssn = '123-45-6789'")
    assert ("ssn", "public.users") in cols


def test_columns_deny_alias_shadow_in_where() -> None:
    """`SELECT id AS ssn ... WHERE ssn = ...` reads the restricted `ssn` column
    and must be denied, not allowed via the aliased projection."""
    decision = _decide("SELECT id AS ssn FROM public.users WHERE ssn = '123-45-6789'")
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_alias_shadow_blind_oracle() -> None:
    """The blind boolean-oracle form (LIKE on the shadowed column) must be denied."""
    assert _decide("SELECT id AS ssn FROM public.users WHERE ssn LIKE '1%'").action == "deny"


def test_columns_deny_alias_shadow_in_group_by() -> None:
    """PostgreSQL resolves GROUP BY name ambiguity to the input column, so a bare
    name in GROUP BY that collides with an alias reads the restricted base
    column; fail closed and deny."""
    assert _decide("SELECT id AS ssn FROM public.users GROUP BY ssn").action == "deny"


def test_columns_allow_genuine_order_by_alias_reference() -> None:
    """A true ORDER BY reference to a SELECT output alias is not a base-column
    access (ORDER BY resolves output aliases first) and must remain allowed, so
    the alias-shadow fix does not over-deny legitimate queries."""
    assert _decide("SELECT id AS ssn FROM public.users ORDER BY ssn").action == "allow"


def test_parser_keeps_inner_order_by_restricted_column_under_outer_alias() -> None:
    """An inner subquery's ORDER BY on a base column must be extracted even when an
    OUTER SELECT has a same-named alias. The alias is visible only in its own
    block's ORDER BY, so the inner reference is a real base-column read."""
    cols = _cols(
        "SELECT id AS ssn FROM public.users "
        "WHERE id = (SELECT id FROM public.users ORDER BY ssn LIMIT 1)"
    )
    assert ("ssn", "public.users") in cols


def test_columns_deny_alias_shadow_in_nested_order_by() -> None:
    """Scope-aware guard: an OUTER select alias must not suppress an INNER
    subquery's ORDER BY reference to a restricted base column of the same name."""
    decision = _decide(
        "SELECT id AS ssn FROM public.users "
        "WHERE id = (SELECT id FROM public.users ORDER BY ssn LIMIT 1)"
    )
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


# ---------------------------------------------------------------------------
# F10: quote-aware identifier matching. A QUOTED identifier is case-sensitive in
# standard SQL / Postgres, so `"ID"` is a distinct column from the allowlisted
# lowercase `id` and must NOT be folded onto it (folding let a quoted case-variant
# of an allowlisted name slip past the column gate). Unquoted identifiers still
# fold to lowercase. The change is strictly fail-closed: a quoted mixed-case name
# simply stops matching the lowercased allowlist and is denied under default-deny.
# ---------------------------------------------------------------------------


def test_columns_deny_quoted_case_variant_of_allowlisted_column() -> None:
    # The headline bypass: "ID" is a case-sensitive column distinct from `id`.
    decision = _decide('SELECT "ID" FROM public.users')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_quoted_mixed_case_column() -> None:
    decision = _decide('SELECT "Name" FROM public.users')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_quoted_case_variant_mixed_with_allowed_column() -> None:
    # An allowed column in the same projection must not launder the quoted variant.
    decision = _decide('SELECT id, "NAME" FROM public.users')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_qualified_quoted_case_variant_column() -> None:
    decision = _decide('SELECT "public"."users"."ID" FROM public.users')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_quoted_case_variant_in_update_set() -> None:
    # A quoted SET target parses as a Column with a quoted leaf -> same base-column gate.
    decision = _decide('UPDATE public.users SET "NAME" = 1 WHERE id = 1')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_allow_quoted_lowercase_column() -> None:
    # Quoted but exactly the allowlisted (lowercase) name -> still allowed.
    assert _decide('SELECT "id", "name" FROM public.users WHERE id = 1').action == "allow"


def test_columns_allow_unquoted_mixed_case_still_folds() -> None:
    # Unquoted identifiers fold to lowercase (Postgres/generic), so `ID` == `id`.
    # Explicit guard so nobody later turns unquoted into per-dialect folding.
    assert _decide("SELECT ID FROM public.users WHERE id = 1").action == "allow"


def test_columns_quoted_case_variant_does_not_break_order_by_alias() -> None:
    # TP4 guard: the ORDER-BY output-alias suppression path is unchanged. The
    # projection value is base `id` (allowed); the ORDER BY term resolves to the alias.
    assert _decide('SELECT id AS "ID" FROM public.users ORDER BY "ID"').action == "allow"


def test_columns_deny_quoted_restricted_column_stays_closed() -> None:
    # Fail-closed direction regression: a quoted restricted column stays denied.
    decision = _decide('SELECT "SSN" FROM public.users')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_insert_deny_quoted_case_variant_target_column() -> None:
    from terminus.policy.policy_engine import PolicyConfig

    cfg = PolicyConfig.model_validate(
        {
            "version": "1.0",
            "default_action": "deny",
            "policies": [
                {
                    "id": "ins",
                    "name": "ins",
                    "priority": 50,
                    "match": {"operation": ["INSERT"], "tables": ["public.users"]},
                    "action": "allow",
                }
            ],
        }
    )
    wl = SchemaWhitelist.model_validate(
        {"enabled": True, "tables": [{"public.users": {"columns": ["id", "name"]}}]}
    )
    engine = PolicyEngine(cfg, whitelist=wl)
    # Quoted case-variant target column -> denied.
    assert (
        engine.evaluate(
            parse_sql('INSERT INTO public.users ("ID") VALUES (1)'), agent_id="a"
        ).action
        == "deny"
    )
    # Quoted-lowercase target columns -> allowed (exact match).
    assert (
        engine.evaluate(
            parse_sql('INSERT INTO public.users ("id", "name") VALUES (1, \'a\')'),
            agent_id="a",
        ).action
        == "allow"
    )


def test_column_role_tracks_case_sensitivity_of_quoted_identifier() -> None:
    # facts.py role tagging must agree with the deny decision: a quoted case-variant
    # is "restricted", not "allowlisted" (the role must not re-lowercase the name).
    from terminus.signature.facts import RoleResolver

    wl = SchemaWhitelist.model_validate(
        {"enabled": True, "tables": [{"public.users": {"columns": ["id", "name"]}}]}
    )
    resolver = RoleResolver(wl)
    restr = resolver.restrictions_for(["public.users"])
    assert resolver.column_role("public.users", "ID", restr) == "restricted"
    assert resolver.column_role("public.users", "id", restr) == "allowlisted"


def test_columns_qualified_star_does_not_raise_with_quote_aware_key() -> None:
    # Star guard: `t.*` has a Star leaf (no .quoted); the quote-aware key must not raise.
    decision = _decide("SELECT u.* FROM public.users u")
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_quoted_order_by_shadows_restricted_via_case_variant_alias() -> None:
    # A quoted ORDER BY term that differs only in case from a quoted output alias is a
    # DISTINCT identifier (Postgres case-sensitivity): `"ssn"` does not resolve to the
    # `"SSN"` output alias, so it is a base-column read of restricted `ssn` (a blind-
    # oracle sort channel) and must be denied, not suppressed as an alias reference.
    decision = _decide('SELECT id AS "SSN" FROM public.users ORDER BY "ssn"')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_deny_quoted_order_by_case_variant_of_unquoted_alias() -> None:
    # Output alias `ssn` (unquoted) vs quoted `"SSN"` in ORDER BY: a case-sensitive
    # mismatch, so the ORDER BY term is a base-column read, not an alias reference.
    decision = _decide('SELECT id AS ssn FROM public.users ORDER BY "SSN"')
    assert decision.action == "deny"
    assert decision.reason_code == "column_whitelist"


def test_columns_allow_quoted_order_by_alias_exact_case_match() -> None:
    # A quoted ORDER BY term that EXACTLY matches a quoted output alias IS a genuine
    # alias reference and stays allowed (the quote-aware guard must not over-deny).
    assert _decide('SELECT id AS "ssn" FROM public.users ORDER BY "ssn"').action == "allow"


# ---------------------------------------------------------------------------
# Task 1: Pure wildcard rewriter
# ---------------------------------------------------------------------------

_USERS_R = {"public.users": {"id", "name", "email"}}


def test_rewrite_bare_star_single_restricted_table() -> None:
    out = rewrite_wildcard("SELECT * FROM public.users", _USERS_R)
    assert out == "SELECT email, id, name FROM public.users"


def test_rewrite_qualified_star() -> None:
    out = rewrite_wildcard("SELECT u.* FROM public.users u", _USERS_R)
    assert out == "SELECT u.email, u.id, u.name FROM public.users AS u"


def test_rewrite_mixed_only_restricted_star_expands() -> None:
    out = rewrite_wildcard(
        "SELECT u.*, o.total FROM public.users u JOIN public.orders o ON u.id = o.user_id",
        _USERS_R,
    )
    assert out is not None
    assert "u.email, u.id, u.name" in out
    assert "o.total" in out
    assert "u.*" not in out


def test_rewrite_both_stars_restricted_expand() -> None:
    restrictions = {"public.users": {"id", "name"}, "public.orders": {"total"}}
    out = rewrite_wildcard(
        "SELECT u.*, o.* FROM public.users u JOIN public.orders o ON u.id = o.user_id",
        restrictions,
    )
    assert out is not None
    assert "u.id, u.name" in out
    assert "o.total" in out
    assert ".*" not in out


def test_rewrite_bare_star_multi_table_returns_none() -> None:
    out = rewrite_wildcard(
        "SELECT * FROM public.users u JOIN public.orders o ON u.id = o.user_id", _USERS_R
    )
    assert out is None


def test_rewrite_star_on_unrestricted_table_returns_none() -> None:
    assert rewrite_wildcard("SELECT o.* FROM public.orders o", _USERS_R) is None


def test_rewrite_no_restrictions_returns_none() -> None:
    assert rewrite_wildcard("SELECT * FROM public.users", {}) is None


def test_rewrite_non_select_returns_none() -> None:
    assert rewrite_wildcard("DROP TABLE public.users", _USERS_R) is None


def test_rewrite_unparseable_returns_none() -> None:
    assert rewrite_wildcard("SELECT FROM WHERE )(", _USERS_R) is None


def test_rewrite_output_reparses() -> None:
    import sqlglot

    out = rewrite_wildcard("SELECT * FROM public.users", _USERS_R)
    assert out is not None
    assert isinstance(sqlglot.parse_one(out), sqlglot.exp.Select)


def test_rewrite_mixed_qualified_stars_one_unrestricted_returns_none() -> None:
    """Any qualified star that cannot be expanded (unrestricted table) -> None."""
    out = rewrite_wildcard(
        "SELECT u.*, o.* FROM public.users u JOIN public.orders o ON u.id = o.user_id",
        {"public.users": {"id", "name", "email"}},  # only users restricted
    )
    assert out is None


def test_rewrite_bare_star_over_derived_table_returns_none() -> None:
    # The outer `*` refers to the subquery alias, not the inner base table, so
    # enumerating base-table columns would yield non-runnable SQL -> withhold.
    out = rewrite_wildcard(
        "SELECT * FROM (SELECT id, name FROM public.users) sub",
        {"public.users": {"id", "name", "email"}},
    )
    assert out is None


# ---------------------------------------------------------------------------
# Task 2: PolicyEngine.suggest_rewrite
# ---------------------------------------------------------------------------


def test_suggest_rewrite_offers_revalidated_sql() -> None:
    engine = PolicyEngine.from_default_policy()
    sql = "SELECT * FROM public.users"
    decision = engine.evaluate(parse_sql(sql), agent_id="analytics_agent_42")
    assert decision.reason_code == "column_whitelist"
    suggested = engine.suggest_rewrite(parse_sql(sql), sql, decision, agent_id="analytics_agent_42")
    assert suggested == "SELECT email, id, name FROM public.users"
    # the offered rewrite itself re-validates to allow
    assert engine.evaluate(parse_sql(suggested), agent_id="analytics_agent_42").action == "allow"


def test_suggest_rewrite_withholds_when_rewrite_still_denied() -> None:
    # Safety guarantee: an agent with no allow rule for the table still gets a
    # wildcard column denial, but the enumerated rewrite would default-deny on
    # policy, so no suggestion is offered.
    engine = PolicyEngine.from_default_policy()
    sql = "SELECT * FROM public.users"
    decision = engine.evaluate(parse_sql(sql), agent_id="random_agent")
    assert decision.reason_code == "column_whitelist"
    suggested = engine.suggest_rewrite(parse_sql(sql), sql, decision, agent_id="random_agent")
    assert suggested is None


def test_suggest_rewrite_none_for_non_wildcard_denial() -> None:
    engine = PolicyEngine.from_default_policy()
    sql = "DROP TABLE public.users"
    decision = engine.evaluate(parse_sql(sql), agent_id="analytics_agent_42")
    assert (
        engine.suggest_rewrite(parse_sql(sql), sql, decision, agent_id="analytics_agent_42") is None
    )


def test_suggest_rewrite_none_for_allow() -> None:
    engine = PolicyEngine.from_default_policy()
    sql = "SELECT id FROM public.users WHERE id = 1"
    decision = engine.evaluate(parse_sql(sql), agent_id="analytics_agent_42")
    assert decision.action == "allow"
    assert (
        engine.suggest_rewrite(parse_sql(sql), sql, decision, agent_id="analytics_agent_42") is None
    )


def test_registry_is_active_for_active_agent() -> None:
    reg = AgentRegistry.model_validate(
        {"agents": [{"id": "analytics_agent_42"}, {"id": "old", "status": "disabled"}]}
    )
    assert reg.is_active("analytics_agent_42") is True
    assert reg.is_active("old") is False
    assert reg.is_active("never_registered") is False


def test_registry_accepts_forward_compat_metadata() -> None:
    # Extra per-agent fields are accepted (ignored in v1), not a validation error.
    reg = AgentRegistry.model_validate(
        {"agents": [{"id": "a", "policy_profile": "readonly", "owner": "data-team"}]}
    )
    assert reg.is_active("a") is True


def test_registry_default_status_is_active() -> None:
    reg = AgentRegistry.model_validate({"agents": [{"id": "a"}]})
    assert reg.agents[0].status == "active"


# ---------------------------------------------------------------------------
# Task 2: Token verification and minting
# ---------------------------------------------------------------------------

_SECRET = "test-jwt-secret-at-least-32-bytes-long-xxxxx"
_REG = AgentRegistry.model_validate({"agents": [{"id": "analytics_agent_42"}]})


def test_mint_then_verify_round_trips() -> None:
    token = mint_token("analytics_agent_42", _SECRET, expires_in=timedelta(hours=1))
    result = verify_token(token, _SECRET, _REG)
    assert result == AuthResult(ok=True, agent_id="analytics_agent_42", reason=None)


def test_verify_rejects_bad_signature() -> None:
    token = mint_token("analytics_agent_42", _SECRET)
    assert verify_token(token, "different-secret-also-32-bytes-long-xxxxx", _REG).ok is False


def test_verify_rejects_expired() -> None:
    token = mint_token("analytics_agent_42", _SECRET, expires_in=timedelta(seconds=-1))
    res = verify_token(token, _SECRET, _REG)
    assert res.ok is False
    assert res.reason == "invalid_token"


def test_verify_rejects_alg_none() -> None:
    # algorithm-confusion / alg=none attack must be rejected by pinning.
    forged = _jwt.encode({"sub": "analytics_agent_42"}, key="", algorithm="none")
    assert verify_token(forged, _SECRET, _REG).ok is False


def test_verify_rejects_missing_sub() -> None:
    token = _jwt.encode({"foo": "bar"}, _SECRET, algorithm="HS256")
    assert verify_token(token, _SECRET, _REG).ok is False


def test_verify_rejects_unknown_sub() -> None:
    token = mint_token("not_registered", _SECRET, expires_in=timedelta(hours=1))
    res = verify_token(token, _SECRET, _REG)
    assert res.ok is False
    assert res.reason == "unknown_agent"


def test_verify_rejects_disabled_sub() -> None:
    reg = AgentRegistry.model_validate({"agents": [{"id": "x", "status": "disabled"}]})
    token = mint_token("x", _SECRET, expires_in=timedelta(hours=1))
    assert verify_token(token, _SECRET, reg).ok is False


def test_mint_without_expiry_is_verifiable() -> None:
    # Valid ONLY on the non-hardened path: staging/production default to
    # require_exp=True and reject this token (see tests/test_jwt_expiry.py).
    token = mint_token("analytics_agent_42", _SECRET, expires_in=None)
    assert verify_token(token, _SECRET, _REG, require_exp=False).ok is True


# ---------------------------------------------------------------------------
# Task 5: Issuance CLI
# ---------------------------------------------------------------------------


def test_cli_issues_token_for_registered_agent(monkeypatch, capsys, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    reset_auth_caches()
    rc = auth_cli_main(["issue", "--agent", "analytics_agent_42"])
    assert rc == 0
    # stdout must be EXACTLY one line, the token: operators capture it with
    # TOKEN=$(python -m terminus.auth issue ...). Incidental logging (e.g. the
    # GAPS L3 policy_limit_not_enforced warning the governance build emits for
    # examples/policy.yaml) is redirected to stderr by the CLI.
    stdout_lines = capsys.readouterr().out.splitlines()
    assert len(stdout_lines) == 1
    token = stdout_lines[0]
    from terminus.auth.registry import get_registry
    from terminus.auth.tokens import verify_token

    assert verify_token(token, _SECRET, get_registry()).agent_id == "analytics_agent_42"


def test_cli_refuses_unregistered_agent(monkeypatch, capsys, reset_auth_caches) -> None:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _SECRET)
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    reset_auth_caches()
    rc = auth_cli_main(["issue", "--agent", "not_registered"])
    assert rc == 1
    out = capsys.readouterr()
    # stdout must be COMPLETELY empty on refusal: no token, and any incidental
    # logging is redirected to stderr by the CLI.
    assert out.out == ""


# --- F11: enforce operation-based rules on writes nested in a CTE ---
#
# A data-modifying statement (INSERT/UPDATE/DELETE/MERGE) hidden in a CTE under a
# top-level SELECT was classified by the top-level operation only, so the
# operation-based policy rules (e.g. block_all_destructive_operations) never saw
# the nested write and it was allowed to run. The parser now surfaces nested
# write operations and the engine fails closed on them.
#
# Detection is by CTE body, NOT find_all(write) minus root: a top-level MERGE
# decomposes into Insert/Update arm nodes that a naive find_all would wrongly
# report as nested writes, which would break any policy that allows MERGE.


def test_parser_surfaces_nested_write_operations() -> None:
    d = parse_sql("WITH d AS (DELETE FROM public.users WHERE id = 1 RETURNING id) SELECT 1")
    assert d.nested_write_operations == ["DELETE"]
    # No nested write in a read-only CTE, a top-level INSERT ... SELECT, or an upsert.
    assert (
        parse_sql(
            "WITH r AS (SELECT id FROM public.users) SELECT id FROM r"
        ).nested_write_operations
        == []
    )
    assert (
        parse_sql(
            "INSERT INTO public.users (id, name) SELECT id, name FROM public.orders"
        ).nested_write_operations
        == []
    )
    assert (
        parse_sql(
            "INSERT INTO public.users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET name = 'x'"
        ).nested_write_operations
        == []
    )


def test_parser_top_level_merge_is_not_a_nested_write() -> None:
    # Regression guard for the detection strategy: a top-level MERGE's WHEN arms
    # are real Insert/Update nodes. They must NOT be counted as nested writes.
    p = parse_sql(
        "MERGE INTO public.users t USING (SELECT 1 AS id) s ON t.id = s.id "
        "WHEN MATCHED THEN UPDATE SET name = 'x' "
        "WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, 'x')"
    )
    assert p.operation == "MERGE"
    assert p.nested_write_operations == []


def test_deny_writable_cte_delete_bypass() -> None:
    # The canonical F11 repro: a DELETE hidden in a CTE under a top-level SELECT.
    d = _decide("WITH d AS (DELETE FROM public.users WHERE id = 1 RETURNING id) SELECT 1")
    assert d.action == "deny"
    assert d.reason_code == "nested_write"


def test_deny_writable_cte_update_bypass() -> None:
    # UPDATE to an allowed column: the bypass is the operation, not the column.
    d = _decide("WITH u AS (UPDATE public.users SET name = 'x' WHERE id = 1 RETURNING id) SELECT 1")
    assert d.action == "deny"
    assert d.reason_code == "nested_write"


def test_deny_writable_cte_insert_on_unrestricted_table() -> None:
    # public.orders is unrestricted, so the column gate does not fire; the
    # nested-write gate is what must catch this.
    d = _decide("WITH i AS (INSERT INTO public.orders (id) VALUES (1) RETURNING id) SELECT 1")
    assert d.action == "deny"
    assert d.reason_code == "nested_write"


def test_deny_writable_cte_merge_bypass() -> None:
    d = _decide(
        "WITH m AS (MERGE INTO public.orders t USING (SELECT 1 AS id) s ON t.id = s.id "
        "WHEN NOT MATCHED THEN INSERT (id) VALUES (s.id)) SELECT 1"
    )
    assert d.action == "deny"
    assert d.reason_code == "nested_write"


def test_deny_top_level_write_smuggling_nested_write() -> None:
    # A top-level, otherwise-allowed INSERT must not let a nested DELETE execute.
    d = _decide(
        "WITH d AS (DELETE FROM public.orders WHERE id = 1 RETURNING id) "
        "INSERT INTO public.orders (id) VALUES (1)"
    )
    assert d.action == "deny"
    assert d.reason_code == "nested_write"
