"""ADVERSARIAL: no real identifier or literal may appear in an outbound payload.

(CI must run this.)
"""

from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine
from terminus.signature.facts import RoleResolver
from terminus.signature.outbound import _to_payload
from terminus.signature.signature import build_signature, fingerprint_for

SENSITIVE = ["patients", "ssn", "hiv_status", "password_hash", "super-secret-value", "users"]


def _payload_json(sql: str) -> str:
    parsed = parse_sql(sql, collect_signature_facts=True)
    engine = PolicyEngine.from_default_policy()
    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")

    _fp, facts, _technique = fingerprint_for(parsed, RoleResolver(engine.whitelist))
    signature = build_signature(facts, decision)
    return _to_payload(signature).model_dump_json()


def test_no_identifiers_unlisted_table() -> None:
    body = _payload_json("SELECT ssn, hiv_status FROM patients WHERE ssn = 'super-secret-value'")
    for token in SENSITIVE:
        assert token not in body, f"leaked: {token}"


def test_no_identifiers_restricted_column() -> None:
    body = _payload_json(
        "SELECT password_hash FROM public.users WHERE password_hash = 'super-secret-value'"
    )
    for token in SENSITIVE:
        assert token not in body, f"leaked: {token}"
