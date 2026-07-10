"""F10c dialect-aware identifier matching."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import terminus.config.settings as settings_mod
from terminus.config.settings import TerminusSettings, assert_known_dialect
from terminus.main import app
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyConfig, PolicyEngine, SchemaWhitelist


def test_sql_dialect_defaults_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    settings_mod._settings = None
    assert settings_mod.get_settings().sql_dialect == ""
    settings_mod._settings = None


def test_sql_dialect_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_SQL_DIALECT", "snowflake")
    settings_mod._settings = None
    assert settings_mod.get_settings().sql_dialect == "snowflake"
    settings_mod._settings = None


def test_assert_known_dialect_accepts_empty_and_known() -> None:
    assert_known_dialect(TerminusSettings(sql_dialect=""))
    assert_known_dialect(TerminusSettings(sql_dialect="snowflake"))
    assert_known_dialect(TerminusSettings(sql_dialect="postgres"))


def test_assert_known_dialect_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="TERMINUS_SQL_DIALECT"):
        assert_known_dialect(TerminusSettings(sql_dialect="bogus_db"))


def test_generic_dialect_folds_unquoted_lower_preserves_quoted() -> None:
    # Default (generic) == the removed F10/F10b behavior.
    p = parse_sql('SELECT ID, "Email" FROM Public.Users WHERE ID = 1')
    assert p.tables == ["public.users"]
    names = {c.name for c in p.columns}
    assert "id" in names  # unquoted folded to lower
    assert "Email" in names  # quoted preserved


def test_snowflake_dialect_folds_unquoted_upper() -> None:
    p = parse_sql('SELECT id, "Email" FROM public.users WHERE id = 1', dialect="snowflake")
    assert p.tables == ["PUBLIC.USERS"]  # unquoted folded to UPPER on Snowflake
    names = {c.name for c in p.columns}
    assert "ID" in names
    assert "Email" in names  # quoted preserved


def test_snowflake_quoted_lowercase_stays_lower() -> None:
    # The fail-open vector's identifier: quoted lowercase stays distinct from the
    # uppercase canonical object.
    p = parse_sql('SELECT id FROM "public"."users"', dialect="snowflake")
    assert p.tables == ["public.users"]  # preserved, distinct from PUBLIC.USERS


def _engine(dialect: str) -> PolicyEngine:
    cfg = PolicyConfig.model_validate(
        {
            "version": "1.0",
            "policies": [
                {
                    "id": "s",
                    "name": "s",
                    "priority": 50,
                    "match": {"operation": ["SELECT"], "tables": ["public.*"]},
                    "action": "allow",
                }
            ],
        },
        context={"dialect": dialect},
    )
    wl = SchemaWhitelist.model_validate(
        {"enabled": True, "tables": ["public.users"]}, context={"dialect": dialect}
    )
    return PolicyEngine(cfg, whitelist=wl)


def test_snowflake_whitelist_denies_distinct_quoted_lowercase_object() -> None:
    eng = _engine("snowflake")
    # canonical (unquoted or quoted-uppercase) -> allow; distinct quoted-lowercase -> deny
    assert (
        eng.evaluate(
            parse_sql("SELECT id FROM public.users", dialect="snowflake"), agent_id="a"
        ).action
        == "allow"
    )
    assert (
        eng.evaluate(
            parse_sql('SELECT id FROM "PUBLIC"."USERS"', dialect="snowflake"), agent_id="a"
        ).action
        == "allow"
    )
    d = eng.evaluate(
        parse_sql('SELECT id FROM "public"."users"', dialect="snowflake"), agent_id="a"
    )
    assert d.action == "deny"
    assert d.reason_code == "schema_whitelist"


def test_generic_whitelist_unchanged() -> None:
    eng = _engine("")
    assert eng.evaluate(parse_sql("SELECT id FROM public.users"), agent_id="a").action == "allow"
    assert eng.evaluate(parse_sql('SELECT id FROM "public"."USERS"'), agent_id="a").action == "deny"


def test_normalize_config_pattern_is_glob_aware() -> None:
    from terminus.policy.policy_engine import _normalize_config_pattern

    assert _normalize_config_pattern("analytics.*", "") == "analytics.*"
    assert _normalize_config_pattern("analytics.*", "snowflake") == "ANALYTICS.*"
    assert _normalize_config_pattern("public.users", "snowflake") == "PUBLIC.USERS"


def _reset() -> None:
    settings_mod._settings = None
    import terminus.config.governance as gov

    gov.get_governance_manager.cache_clear()


def test_payload_dialect_never_drives_normalization_or_whitelist_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRITICAL #1 regression: payload.dialect must never drive identifier
    normalization / whitelist matching, even when TERMINUS_SQL_DIALECT is unset
    (the default deployment).

    "public"."USERS" (quoted) is NOT public.users under the trusted generic
    dialect -- it must be denied at the schema whitelist regardless of what the
    attacker-controlled request body claims its dialect is. Before the fix, a
    request that sets dialect="duckdb" folds the quoted "USERS" to lowercase and
    the query is wrongly allowed.
    """
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.delenv("TERMINUS_SQL_DIALECT", raising=False)
    _reset()
    client = TestClient(app)
    r = client.post(
        "/intercept",
        json={
            "sql": 'SELECT id FROM "public"."USERS" WHERE id = 1',
            "agent_id": "analytics_agent_42",
            "dialect": "duckdb",
        },
    )
    assert r.status_code == 403
    body = r.json()
    assert body["decision"] == "deny"
    assert body["policy_id"] == "schema_whitelist"
    _reset()


def test_suggest_rewrite_normalizes_reparsed_sql_generic_dialect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IMPORTANT #2 regression: rewrite_wildcard's re-parse must normalize
    identifiers so the rewritten table/column names match the (normalized)
    restrictions keys, even on the generic (unset TERMINUS_SQL_DIALECT) dialect.

    Before the fix, the re-parse leaves `Public.Users` mixed-case, it never
    matches the normalized `public.users` restrictions key, and suggest_rewrite
    silently returns None (no remediation.suggested_sql) instead of an enumerated
    rewrite.
    """
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.delenv("TERMINUS_SQL_DIALECT", raising=False)
    _reset()
    client = TestClient(app)
    r = client.post(
        "/intercept",
        json={
            "sql": "SELECT * FROM Public.Users WHERE id = 1",
            "agent_id": "analytics_agent_42",
        },
    )
    assert r.status_code == 403
    body = r.json()
    assert body["decision"] == "deny"
    remediation = body.get("remediation")
    assert remediation is not None
    assert remediation.get("suggested_sql") is not None
    _reset()


def test_assert_known_dialect_rejects_alias_only_dialect() -> None:
    """Minor regression: `singlestore` is accepted by Dialect.get_or_raise (it is
    registered in sqlglot's dialect class registry) but is NOT a value of the
    `Dialects` enum, so it is absent from parse_sql's KNOWN_DIALECTS. Without this
    guard, TERMINUS_SQL_DIALECT=singlestore would boot successfully and then
    parse_sql would return invalid_sql for every single query -- a fail-closed
    self-inflicted denial of service.
    """
    from sqlglot.dialects.dialect import Dialect

    from terminus.parser.sql_parser import KNOWN_DIALECTS

    assert Dialect.get_or_raise("singlestore") is not None  # sanity: sqlglot accepts it
    assert "singlestore" not in KNOWN_DIALECTS  # sanity: parse_sql would reject it
    with pytest.raises(ValueError, match="TERMINUS_SQL_DIALECT"):
        assert_known_dialect(TerminusSettings(sql_dialect="singlestore"))


def test_snowflake_deployment_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    # Whitelist ships public.users (lowercase in YAML). On Snowflake that means the
    # PUBLIC.USERS object; a distinct quoted-lowercase object must be denied.
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    monkeypatch.setenv("TERMINUS_SQL_DIALECT", "snowflake")
    _reset()
    client = TestClient(app)
    # canonical, unquoted -> allowed
    r_ok = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users WHERE id = 1", "agent_id": "analytics_agent_42"},
    )
    assert r_ok.json()["decision"] == "allow"
    # distinct quoted-lowercase object -> denied at the whitelist
    r_bad = client.post(
        "/intercept",
        json={
            "sql": 'SELECT id FROM "public"."users" WHERE id = 1',
            "agent_id": "analytics_agent_42",
        },
    )
    assert r_bad.status_code == 403
    assert r_bad.json()["decision"] == "deny"
    _reset()
