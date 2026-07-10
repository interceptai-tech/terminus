"""OutboundBuffer overflow + OutboundEmitter guard behavior."""

from terminus.signature.outbound import OutboundBuffer, OutboundEmitter, _to_payload
from terminus.signature.signature import Signature, SignatureStructure


def _structure(**over: object) -> SignatureStructure:
    base = {
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
    base.update(over)
    return SignatureStructure(**base)


def _signature(**over: object) -> Signature:
    base = {
        "query_fingerprint": "fp",
        "operation": "SELECT",
        "decision": "deny",
        "reason_code": "default",
        "risk_score": 0.9,
        "risk_reasons": [],
        "technique": None,
        "structure": _structure(),
        "security_flags": [],
        "smuggling_markers": [],
        "emitted_at": "2026-06-22T14:00:00Z",
    }
    base.update(over)
    return Signature(**base)


def _payload():  # type: ignore
    return _to_payload(_signature())


def test_buffer_drains_oldest_first() -> None:
    buf = OutboundBuffer(maxlen=10)
    buf.append(_payload())
    buf.append(_payload())
    out = buf.drain(batch_max=5)
    assert len(out) == 2
    assert len(buf) == 0


def test_buffer_drops_oldest_when_full() -> None:
    buf = OutboundBuffer(maxlen=2)
    buf.append(_payload())
    buf.append(_payload())
    buf.append(_payload())  # overflow: oldest dropped
    assert len(buf) == 2


def test_drain_respects_batch_max() -> None:
    buf = OutboundBuffer(maxlen=10)
    for _ in range(5):
        buf.append(_payload())
    assert len(buf.drain(batch_max=3)) == 3
    assert len(buf) == 2


def test_emitter_enqueues_clean_signature() -> None:
    buf = OutboundBuffer(maxlen=10)
    OutboundEmitter(buf).emit(_signature())
    assert len(buf) == 1


def test_emitter_drops_leaky_signature_without_enqueue() -> None:
    buf = OutboundBuffer(maxlen=10)
    # An out-of-vocabulary role trips _assert_privacy; it must not be enqueued.
    bad = _signature(structure=_structure(predicate_roles=["patients.ssn"]))
    OutboundEmitter(buf).emit(bad)
    assert len(buf) == 0
