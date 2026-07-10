"""ADVERSARIAL: no real identifier or literal may appear in a signature. (CI must run this.)"""

from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine
from terminus.signature.facts import RoleResolver, to_signature_facts
from terminus.signature.signature import build_signature

SENSITIVE = ["patients", "ssn", "hiv_status", "password_hash", "super-secret-value", "users"]


def _signature_json(sql: str) -> str:
    parsed = parse_sql(sql, collect_signature_facts=True)
    engine = PolicyEngine.from_default_policy()
    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")
    resolver = RoleResolver(engine.whitelist)
    facts = to_signature_facts(parsed, resolver)
    return build_signature(facts, decision).model_dump_json()


def test_no_identifiers_unlisted_table() -> None:
    body = _signature_json("SELECT ssn, hiv_status FROM patients WHERE ssn = 'super-secret-value'")
    for token in SENSITIVE:
        assert token not in body, f"leaked: {token}"


def test_no_identifiers_restricted_column() -> None:
    body = _signature_json(
        "SELECT password_hash FROM public.users WHERE password_hash = 'super-secret-value'"
    )
    for token in SENSITIVE:
        assert token not in body, f"leaked: {token}"


def test_no_identifiers_multitable_aliased_join() -> None:
    body = _signature_json(
        "SELECT p.ssn, v.diagnosis FROM patients p "
        "JOIN visits v ON p.id = v.patient_id "
        "WHERE v.diagnosis = 'cancer-dx'"
    )
    for token in ["patients", "visits", "ssn", "diagnosis", "patient_id", "cancer-dx"]:
        assert token not in body, f"leaked: {token}"
