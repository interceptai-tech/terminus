"""Signature model, deterministic fingerprint, and privacy guard."""

import pytest

from terminus.signature.facts import SignatureFacts
from terminus.signature.signature import (
    PrivacyGuardError,
    Signature,
    SignatureStructure,
    _assert_privacy,
    query_fingerprint,
)


def _facts(**over) -> SignatureFacts:
    base = {
        "operation": "SELECT",
        "has_where": True,
        "has_aggregate": True,
        "aggregate_only": True,
        "has_subquery": False,
        "has_union": False,
        "join_count": 0,
        "wildcard": "none",
        "predicate_ops": ("LIKE",),
        "projection_roles": ("aggregate",),
        "predicate_roles": ("restricted",),
        "table_roles": ("restricted",),
        "security_flags": (),
        "smuggling_markers": (),
        "risk_score": 0.85,
        "risk_reasons": (),
    }
    base.update(over)
    return SignatureFacts(**base)


def test_fingerprint_is_deterministic() -> None:
    assert query_fingerprint(_facts(), "aggregate_oracle_probe") == query_fingerprint(
        _facts(), "aggregate_oracle_probe"
    )


def test_fingerprint_ignores_risk_score() -> None:
    a = query_fingerprint(_facts(risk_score=0.85), "aggregate_oracle_probe")
    b = query_fingerprint(_facts(risk_score=0.10), "aggregate_oracle_probe")
    assert a == b  # risk_score is excluded from the hash


def test_fingerprint_changes_with_structure() -> None:
    a = query_fingerprint(_facts(aggregate_only=True), "aggregate_oracle_probe")
    b = query_fingerprint(_facts(aggregate_only=False), "aggregate_oracle_probe")
    assert a != b


def test_fingerprint_changes_with_technique() -> None:
    assert query_fingerprint(_facts(), "aggregate_oracle_probe") != query_fingerprint(
        _facts(), None
    )


def _signature(**struct_over) -> Signature:
    struct = {
        "has_where": True,
        "has_aggregate": True,
        "aggregate_only": True,
        "has_subquery": False,
        "has_union": False,
        "join_count": 0,
        "wildcard": "none",
        "predicate_ops": ["LIKE"],
        "projection_roles": ["aggregate"],
        "predicate_roles": ["restricted"],
        "table_roles": ["restricted"],
    }
    struct.update(struct_over)
    return Signature(
        query_fingerprint="deadbeef",
        operation="SELECT",
        decision="deny",
        reason_code="column_whitelist",
        risk_score=0.85,
        risk_reasons=[],
        technique="aggregate_oracle_probe",
        structure=SignatureStructure(**struct),
        security_flags=[],
        smuggling_markers=[],
        emitted_at="2026-06-22T00:00:00Z",
    )


def test_assert_privacy_passes_clean_signature() -> None:
    _assert_privacy(_signature())  # no raise


def test_assert_privacy_trips_on_leaked_identifier() -> None:
    with pytest.raises(PrivacyGuardError) as exc:
        _assert_privacy(_signature(predicate_roles=["patients.ssn"]))
    assert exc.value.field == "structure.predicate_roles"


def test_assert_privacy_trips_on_bad_technique() -> None:
    sig = _signature().model_copy(update={"technique": "injected_technique"})
    with pytest.raises(PrivacyGuardError) as exc:
        _assert_privacy(sig)
    assert exc.value.field == "technique"


def test_assert_privacy_trips_on_bad_security_flag() -> None:
    sig = _signature().model_copy(update={"security_flags": ["patients.ssn"]})
    with pytest.raises(PrivacyGuardError) as exc:
        _assert_privacy(sig)
    assert exc.value.field == "security_flags"
