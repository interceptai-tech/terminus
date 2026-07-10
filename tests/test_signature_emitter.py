"""Emitter logs clean signatures and drops leaky ones (fail closed)."""

import structlog

from terminus.signature.emitter import LogSignatureEmitter, get_signature_emitter
from terminus.signature.signature import Signature, SignatureStructure


def _sig(**struct_over) -> Signature:
    struct = {
        "has_where": True,
        "has_aggregate": False,
        "aggregate_only": False,
        "has_subquery": False,
        "has_union": False,
        "join_count": 0,
        "wildcard": "none",
        "predicate_ops": ["EQ"],
        "projection_roles": ["allowlisted"],
        "predicate_roles": ["allowlisted"],
        "table_roles": ["allowlisted"],
    }
    struct.update(struct_over)
    return Signature(
        query_fingerprint="abc",
        operation="SELECT",
        decision="deny",
        reason_code="default",
        risk_score=0.9,
        risk_reasons=[],
        technique=None,
        structure=SignatureStructure(**struct),
        security_flags=[],
        smuggling_markers=[],
        emitted_at="2026-06-22T00:00:00Z",
    )


def test_emits_clean_signature(capsys) -> None:
    structlog.reset_defaults()
    LogSignatureEmitter().emit(_sig())
    out = capsys.readouterr().out
    assert "terminus_signature" in out
    assert "abc" in out  # the fingerprint


def test_drops_leaky_signature(capsys) -> None:
    structlog.reset_defaults()
    LogSignatureEmitter().emit(_sig(predicate_roles=["patients.ssn"]))
    out = capsys.readouterr().out
    assert "signature_privacy_guard_tripped" in out
    assert "structure.predicate_roles" in out  # the field name
    assert "patients.ssn" not in out  # the leaky value is NEVER logged
    assert "terminus_signature" not in out


def test_get_signature_emitter_returns_emitter() -> None:
    assert hasattr(get_signature_emitter(), "emit")
