"""fingerprint_for and the floor-and-tighten matcher."""

from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyDecision, PolicyEngine
from terminus.signature.facts import RoleResolver
from terminus.signature.matcher import evaluate_match
from terminus.signature.records import SignatureRecord
from terminus.signature.signature import fingerprint_for
from terminus.signature.store import SignatureStore


def _fp(sql: str) -> str:
    engine = PolicyEngine.from_default_policy()
    parsed = parse_sql(sql, collect_signature_facts=True)
    fp, _facts, _technique = fingerprint_for(parsed, RoleResolver(engine.whitelist))
    return fp


def _store_with(fp: str, mode: str) -> SignatureStore:
    s = SignatureStore()
    s.swap(
        [
            SignatureRecord(
                signature_id="sig-1",
                query_fingerprint=fp,
                fingerprint_version="1",
                severity="high",
                mode=mode,
            )
        ]
    )
    return s


def _allow() -> PolicyDecision:
    return PolicyDecision(action="allow", reason="ok", reason_code="policy_rule")


def _deny() -> PolicyDecision:
    return PolicyDecision(action="deny", reason="no", reason_code="default")


def test_no_match_leaves_decision_unchanged() -> None:
    store = _store_with("some-other-fp", "enforce")
    r = evaluate_match("unknown-fp", _allow(), store, enforce_enabled=True)
    assert r.matched is False
    assert r.decision.action == "allow"
    assert r.enforced is False


def test_enforce_match_escalates_allow_to_deny() -> None:
    fp = _fp("SELECT id FROM public.users WHERE id = 1")
    r = evaluate_match(fp, _allow(), _store_with(fp, "enforce"), enforce_enabled=True)
    assert r.matched is True
    assert r.decision.action == "deny"
    assert r.decision.reason_code == "signature_match"
    assert r.enforced is True


def test_observe_match_does_not_change_decision() -> None:
    fp = _fp("SELECT id FROM public.users WHERE id = 1")
    r = evaluate_match(fp, _allow(), _store_with(fp, "observe"), enforce_enabled=True)
    assert r.matched is True
    assert r.decision.action == "allow"  # observe never changes the decision
    assert r.enforced is False


def test_enforce_posture_off_forces_observe() -> None:
    fp = _fp("SELECT id FROM public.users WHERE id = 1")
    r = evaluate_match(fp, _allow(), _store_with(fp, "enforce"), enforce_enabled=False)
    assert r.matched is True
    assert r.decision.action == "allow"  # global posture overrides per-signature enforce
    assert r.enforced is False


def test_match_never_downgrades_a_deny() -> None:
    fp = _fp("SELECT id FROM public.users WHERE id = 1")
    local = _deny()
    r = evaluate_match(fp, local, _store_with(fp, "enforce"), enforce_enabled=True)
    assert r.matched is True  # the fingerprint DID match a stored record
    assert r.decision is local  # never downgraded: same deny object returned
    assert r.decision.action == "deny"
    assert r.enforced is False
