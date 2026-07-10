"""CompositeEmitter fan-out + per-leg exception isolation, and outbound wiring."""

import terminus.config.settings as settings_mod
from terminus.signature.emitter import CompositeEmitter, LogSignatureEmitter, get_signature_emitter
from terminus.signature.outbound import OutboundEmitter
from terminus.signature.signature import Signature, SignatureStructure


def _signature() -> Signature:
    return Signature(
        query_fingerprint="fp",
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
        emitted_at="2026-06-22T14:00:00Z",
    )


class _Boom:
    def emit(self, signature: Signature) -> None:
        raise RuntimeError("leg boom")


class _Record:
    def __init__(self) -> None:
        self.count = 0

    def emit(self, signature: Signature) -> None:
        self.count += 1


def test_composite_isolates_a_raising_leg() -> None:
    good = _Record()
    CompositeEmitter([_Boom(), good]).emit(_signature())  # must not raise
    assert good.count == 1  # the second leg still ran


def test_disabled_returns_single_log_leg(monkeypatch) -> None:
    monkeypatch.setenv("TERMINUS_SIGNATURE_OUTBOUND_ENABLED", "false")
    settings_mod._settings = None
    emitter = get_signature_emitter()
    assert isinstance(emitter, CompositeEmitter)
    assert len(emitter._legs) == 1
    assert isinstance(emitter._legs[0], LogSignatureEmitter)
    settings_mod._settings = None


def test_enabled_adds_outbound_leg(monkeypatch) -> None:
    monkeypatch.setenv("TERMINUS_SIGNATURE_OUTBOUND_ENABLED", "true")
    settings_mod._settings = None
    emitter = get_signature_emitter()
    assert isinstance(emitter, CompositeEmitter)
    assert any(isinstance(leg, OutboundEmitter) for leg in emitter._legs)
    settings_mod._settings = None
