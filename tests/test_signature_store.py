"""In-memory fingerprint-keyed store with atomic swap."""

from terminus.signature.records import SignatureRecord
from terminus.signature.store import SignatureStore, get_signature_store


def _rec(fp: str, sid: str = "sig") -> SignatureRecord:
    return SignatureRecord(
        signature_id=sid,
        query_fingerprint=fp,
        fingerprint_version="1",
        severity="high",
        mode="observe",
    )


def test_empty_store_misses() -> None:
    assert SignatureStore().lookup("nope") is None


def test_swap_then_lookup() -> None:
    s = SignatureStore()
    s.swap([_rec("fp1"), _rec("fp2")])
    assert s.lookup("fp1") is not None
    assert s.lookup("fp2") is not None
    assert s.lookup("fp3") is None
    assert len(s) == 2


def test_swap_replaces_atomically() -> None:
    s = SignatureStore()
    s.swap([_rec("fp1")])
    s.swap([_rec("fp2")])
    assert s.lookup("fp1") is None  # old set fully replaced
    assert s.lookup("fp2") is not None


def test_get_signature_store_is_singleton() -> None:
    assert get_signature_store() is get_signature_store()
