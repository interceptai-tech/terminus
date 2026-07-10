"""SignatureRecord / SignatureBundle models and FINGERPRINT_VERSION."""

import pytest
from pydantic import ValidationError

from terminus.signature.records import (
    SUPPORTED_BUNDLE_FORMAT_VERSIONS,
    SignatureBundle,
    SignatureRecord,
)
from terminus.signature.signature import FINGERPRINT_VERSION, Signature, SignatureStructure


def _record(**over):
    base = {
        "signature_id": "sig-1",
        "query_fingerprint": "abc",
        "fingerprint_version": "1",
        "technique": "aggregate_oracle_probe",
        "severity": "high",
        "mode": "observe",
        "description": "aggregate probe on a restricted column",
        "first_seen": "2026-06-20",
    }
    base.update(over)
    return SignatureRecord(**base)


def test_record_defaults_source_bundle() -> None:
    assert _record().source == "bundle"


def test_record_rejects_bad_mode() -> None:
    with pytest.raises(ValidationError):
        _record(mode="block")  # only observe | enforce


def test_record_rejects_bad_severity() -> None:
    with pytest.raises(ValidationError):
        _record(severity="catastrophic")


def test_bundle_holds_records() -> None:
    b = SignatureBundle(
        bundle_format_version="1",
        fingerprint_version="1",
        bundle_id="b1",
        issued_at="2026-06-25T00:00:00Z",
        signatures=[_record()],
    )
    assert b.signatures[0].signature_id == "sig-1"
    assert "1" in SUPPORTED_BUNDLE_FORMAT_VERSIONS


def test_fingerprint_version_drives_signature_schema_version() -> None:
    sig = Signature(
        query_fingerprint="x",
        operation="SELECT",
        decision="deny",
        reason_code="default",
        risk_score=0.9,
        risk_reasons=[],
        technique=None,
        structure=SignatureStructure(
            has_where=True,
            has_aggregate=False,
            aggregate_only=False,
            has_subquery=False,
            has_union=False,
            join_count=0,
            wildcard="none",
        ),
        security_flags=[],
        smuggling_markers=[],
        emitted_at="2026-06-22T00:00:00Z",
    )
    assert sig.schema_version == FINGERPRINT_VERSION
