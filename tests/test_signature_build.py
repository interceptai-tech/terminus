"""Technique labeling and Signature assembly."""

from terminus.policy.policy_engine import PolicyDecision
from terminus.signature.facts import SignatureFacts
from terminus.signature.signature import _label_technique, build_signature


def _facts(**over) -> SignatureFacts:
    base = {
        "operation": "SELECT",
        "has_where": True,
        "has_aggregate": False,
        "aggregate_only": False,
        "has_subquery": False,
        "has_union": False,
        "join_count": 0,
        "wildcard": "none",
        "predicate_ops": (),
        "projection_roles": (),
        "predicate_roles": (),
        "table_roles": (),
        "security_flags": (),
        "smuggling_markers": (),
        "risk_score": 0.1,
        "risk_reasons": (),
    }
    base.update(over)
    return SignatureFacts(**base)


def test_label_smuggling_wins_first() -> None:
    f = _facts(smuggling_markers=("sleep(",), aggregate_only=True, predicate_roles=("restricted",))
    assert _label_technique(f) == "smuggling"


def test_label_aggregate_oracle_probe() -> None:
    f = _facts(
        aggregate_only=True, predicate_roles=("restricted",), projection_roles=("aggregate",)
    )
    assert _label_technique(f) == "aggregate_oracle_probe"


def test_label_wildcard_exfiltration() -> None:
    f = _facts(wildcard="bare", table_roles=("allowlisted",))
    assert _label_technique(f) == "wildcard_exfiltration"


def test_label_disallowed_column_access() -> None:
    f = _facts(projection_roles=("restricted",), table_roles=("restricted",))
    assert _label_technique(f) == "disallowed_column_access"


def test_label_destructive_unbounded_ddl() -> None:
    assert _label_technique(_facts(operation="DROP", has_where=False)) == "destructive_unbounded"


def test_label_destructive_unbounded_delete_no_where() -> None:
    assert _label_technique(_facts(operation="DELETE", has_where=False)) == "destructive_unbounded"


def test_label_unlisted_table_access() -> None:
    assert _label_technique(_facts(table_roles=("unlisted",))) == "unlisted_table_access"


def test_label_none_for_benign() -> None:
    assert _label_technique(_facts()) is None


def test_build_signature_maps_fields() -> None:
    f = _facts(
        aggregate_only=True,
        has_aggregate=True,
        predicate_roles=("restricted",),
        projection_roles=("aggregate",),
        predicate_ops=("LIKE",),
        risk_score=0.85,
    )
    decision = PolicyDecision(action="deny", reason="x", reason_code="column_whitelist")
    sig = build_signature(f, decision)
    assert sig.operation == "SELECT"
    assert sig.decision == "deny"
    assert sig.reason_code == "column_whitelist"
    assert sig.risk_score == 0.85
    assert sig.technique == "aggregate_oracle_probe"
    assert sig.structure.predicate_ops == ["LIKE"]
    assert len(sig.query_fingerprint) == 64  # sha256 hex
    assert sig.emitted_at  # stamped
