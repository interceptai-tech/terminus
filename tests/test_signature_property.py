"""Property: the fingerprint is deterministic and structure-sensitive."""

from typing import Any

from terminus.signature.facts import SignatureFacts
from terminus.signature.signature import query_fingerprint


def _facts(**over: Any) -> SignatureFacts:
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


def test_determinism_over_many_shapes() -> None:
    shapes = [
        _facts(),
        _facts(operation="DELETE", has_where=False),
        _facts(wildcard="bare", table_roles=("restricted",)),
        _facts(
            aggregate_only=True,
            has_aggregate=True,
            predicate_roles=("restricted",),
            projection_roles=("aggregate",),
        ),
        _facts(predicate_ops=("EQ", "LIKE"), join_count=2),
    ]
    for f in shapes:
        assert query_fingerprint(f, None) == query_fingerprint(f, None)


def test_each_structural_field_changes_the_hash() -> None:
    base = _facts()
    base_fp = query_fingerprint(base, None)
    assert query_fingerprint(_facts(has_where=False), None) != base_fp
    assert query_fingerprint(_facts(join_count=1), None) != base_fp
    assert query_fingerprint(_facts(wildcard="bare"), None) != base_fp
    assert query_fingerprint(_facts(table_roles=("restricted",)), None) != base_fp
    assert query_fingerprint(_facts(predicate_ops=("EQ",)), None) != base_fp


def test_risk_score_does_not_change_the_hash() -> None:
    assert query_fingerprint(_facts(risk_score=0.1), None) == query_fingerprint(
        _facts(risk_score=0.99), None
    )
