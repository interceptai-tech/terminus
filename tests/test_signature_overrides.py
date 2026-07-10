"""Local overrides: disable, mode override, local-add. Local always wins."""

from terminus.signature.overrides import SignatureOverrides, resolve_active_records
from terminus.signature.records import SignatureRecord


def _rec(sid: str, fp: str, mode: str = "observe", source: str = "bundle") -> SignatureRecord:
    return SignatureRecord(
        signature_id=sid,
        query_fingerprint=fp,
        fingerprint_version="1",
        severity="high",
        mode=mode,
        source=source,
    )


def test_disable_removes_bundle_signature() -> None:
    out = resolve_active_records([_rec("sig-1", "fp1")], SignatureOverrides(disable=["sig-1"]))
    assert out == []


def test_mode_override_wins() -> None:
    out = resolve_active_records(
        [_rec("sig-1", "fp1", mode="observe")],
        SignatureOverrides(mode={"sig-1": "enforce"}),
    )
    assert out[0].mode == "enforce"


def test_local_signature_survives_and_is_added() -> None:
    local = _rec("local-1", "fp-local", source="local")
    out = resolve_active_records([_rec("sig-1", "fp1")], SignatureOverrides(signatures=[local]))
    ids = {r.signature_id for r in out}
    assert ids == {"sig-1", "local-1"}


def test_disabled_local_is_also_removed() -> None:
    local = _rec("local-1", "fp-local", source="local")
    out = resolve_active_records([], SignatureOverrides(signatures=[local], disable=["local-1"]))
    assert out == []
