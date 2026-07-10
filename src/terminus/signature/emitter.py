"""Emit signatures to a dedicated, scrubbed local stream.

The default emitter writes a structured JSON line on the `terminus.signature`
logger (separate from the audit log, which carries identifying fields). The
SignatureEmitter protocol keeps the transport swappable (file, queue, Hub)
later.
"""

from __future__ import annotations

from typing import Protocol

import structlog

from terminus.config.settings import get_settings
from terminus.observability.metrics import record_emitter_error
from terminus.signature.signature import PrivacyGuardError, Signature, _assert_privacy

_log = structlog.get_logger("terminus.signature.emitter")


class SignatureEmitter(Protocol):
    """A sink for privacy-scrubbed signatures."""

    def emit(self, signature: Signature) -> None: ...


class LogSignatureEmitter:
    """Emit on the dedicated `terminus.signature` structlog stream.

    Runs the fail-closed privacy guard immediately before emission: an
    out-of-vocabulary token means drop the signature and log only the offending
    field name, never the value.
    """

    def __init__(self) -> None:
        self._log = structlog.get_logger("terminus.signature")

    def emit(self, signature: Signature) -> None:
        try:
            _assert_privacy(signature)
        except PrivacyGuardError as exc:
            self._log.warning("signature_privacy_guard_tripped", field=exc.field)
            return
        self._log.info("terminus_signature", **signature.model_dump(mode="json"))


class CompositeEmitter:
    """Fan a signature out to multiple emitter legs, isolating each.

    A leg raising never propagates to the caller or affects another leg; it is
    logged and counted. This is always the type get_signature_emitter returns,
    so a future leg (e.g. a metrics emitter) is a one-line addition.
    """

    def __init__(self, legs: list[SignatureEmitter]) -> None:
        self._legs = legs

    def emit(self, signature: Signature) -> None:
        for leg in self._legs:
            try:
                leg.emit(signature)
            except Exception as exc:  # one leg never breaks another or the caller
                _log.warning(
                    "signature_emitter_leg_failed",
                    leg=type(leg).__name__,
                    error=exc.__class__.__name__,
                )
                record_emitter_error(type(leg).__name__)


def get_signature_emitter() -> SignatureEmitter:
    """Always a CompositeEmitter: the log leg, plus the outbound leg when enabled."""
    legs: list[SignatureEmitter] = [LogSignatureEmitter()]
    if get_settings().signature_outbound_enabled:
        from terminus.signature.outbound import OutboundEmitter, get_outbound_buffer

        legs.append(OutboundEmitter(get_outbound_buffer()))
    return CompositeEmitter(legs)
