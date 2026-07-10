"""Outbound + emitter-error metrics increment without error."""

from terminus.observability import metrics


def test_recorders_exist_and_increment() -> None:
    metrics.record_outbound_sent(3)
    metrics.record_outbound_failed(2)
    metrics.record_outbound_dropped()
    metrics.record_outbound_guard_tripped()
    metrics.record_emitter_error("OutboundEmitter")
    # No exception is the contract; values are exercised by the integration tests.
