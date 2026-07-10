"""Role attribution and fact assembly at the privacy chokepoint."""

from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine
from terminus.signature.facts import RoleResolver, to_signature_facts


def _resolver() -> RoleResolver:
    # examples/schema_whitelist.yaml restricts public.users to [id, name, email].
    return RoleResolver(PolicyEngine.from_default_policy().whitelist)


def _facts_for(sql: str):
    parsed = parse_sql(sql, collect_signature_facts=True)
    return to_signature_facts(parsed, _resolver())


def test_oracle_probe_roles() -> None:
    f = _facts_for("SELECT COUNT(*) FROM public.users WHERE password_hash LIKE 'a%'")
    assert "restricted" in f.predicate_roles  # password_hash is restricted
    assert "restricted" not in f.projection_roles  # projection is only the aggregate
    assert "aggregate" in f.projection_roles
    assert f.aggregate_only is True
    assert "restricted" in f.table_roles
    assert f.predicate_ops == ("LIKE",)


def test_unlisted_table_role() -> None:
    f = _facts_for("SELECT a FROM not_on_whitelist WHERE a = 1")
    assert "unlisted" in f.table_roles


def test_allowlisted_column_role() -> None:
    f = _facts_for("SELECT id FROM public.users WHERE id = 1")
    assert "allowlisted" in f.projection_roles
