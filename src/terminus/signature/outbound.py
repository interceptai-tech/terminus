"""Outbound telemetry: ship privacy-scrubbed signatures to a Hub (Phase 2B).

The wire payload is a strict, name-free projection of a Signature that has
already passed the Phase 1 _assert_privacy guard. Nothing here can carry a real
table name, column name, or literal.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import UTC, datetime
from functools import lru_cache

import httpx
import structlog
from pydantic import BaseModel, ConfigDict

from terminus.config.settings import TerminusSettings, get_settings
from terminus.observability.metrics import (
    record_outbound_dropped,
    record_outbound_failed,
    record_outbound_guard_tripped,
    record_outbound_sent,
)
from terminus.signature.signature import (
    PrivacyGuardError,
    Signature,
    SignatureStructure,
    _assert_privacy,
)

_log = structlog.get_logger("terminus.signature.outbound")


class OutboundPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload_version: str = "1"
    query_fingerprint: str
    fingerprint_version: str
    operation: str
    technique: str | None = None
    local_decision: str
    local_risk_score: float | None = None
    observed_at: str
    structure: SignatureStructure


def _to_payload(signature: Signature) -> OutboundPayload:
    """Map a Signature to its name-free outbound payload.

    observed_at is computed here, truncated to the hour (privacy-coarse), so the
    mapping is self-contained and the shipper never re-derives a timestamp.
    """
    observed_at = datetime.now(UTC).replace(minute=0, second=0, microsecond=0).isoformat()
    return OutboundPayload(
        query_fingerprint=signature.query_fingerprint,
        fingerprint_version=signature.schema_version,
        operation=signature.operation,
        technique=signature.technique,
        local_decision=signature.decision,
        local_risk_score=signature.risk_score,
        observed_at=observed_at,
        structure=signature.structure,
    )


class OutboundBuffer:
    """Bounded in-memory queue of pending payloads. Drop-oldest on overflow.

    append() is sync, O(1), and GIL-atomic, called on the request path only for
    that cheap append. drain() runs in the background shipper. Both execute on
    the single event loop, so no locking is needed.
    """

    def __init__(self, maxlen: int) -> None:
        self._dq: deque[OutboundPayload] = deque(maxlen=maxlen)
        self._maxlen = maxlen

    def append(self, payload: OutboundPayload) -> None:
        if len(self._dq) >= self._maxlen:  # full: this append will drop oldest
            record_outbound_dropped()
        self._dq.append(payload)

    def drain(self, batch_max: int) -> list[OutboundPayload]:
        out: list[OutboundPayload] = []
        while self._dq and len(out) < batch_max:
            out.append(self._dq.popleft())  # oldest first
        return out

    def __len__(self) -> int:
        return len(self._dq)


@lru_cache(maxsize=1)
def get_outbound_buffer() -> OutboundBuffer:
    """Process-wide buffer singleton. Only ever built when outbound is enabled."""
    return OutboundBuffer(get_settings().signature_outbound_buffer_max)


class OutboundEmitter:
    """A SignatureEmitter leg that enqueues privacy-scrubbed payloads.

    Re-runs the Phase 1 _assert_privacy guard before enqueue: a signature that
    trips the guard is dropped and never enqueued (fail-closed).
    """

    def __init__(self, buffer: OutboundBuffer) -> None:
        self._buffer = buffer

    def emit(self, signature: Signature) -> None:
        try:
            _assert_privacy(signature)
        except PrivacyGuardError as exc:
            _log.warning("signature_outbound_guard_tripped", field=exc.field)
            record_outbound_guard_tripped()
            return
        self._buffer.append(_to_payload(signature))


MAX_ATTEMPTS = 3
BACKOFF_BASE = 1.0  # seconds; sleep BACKOFF_BASE * 2**attempt between attempts


class OutboundShipper:
    """Background drainer: batch the buffer and POST to the Hub. Best-effort.

    Runs OFF the request path. A POST that succeeds on a retry still counts as
    sent. A batch that exhausts all retries is dropped (counted), never blocks,
    and never raises into the request path.
    """

    def __init__(
        self,
        *,
        buffer: OutboundBuffer,
        url: str,
        token: str,
        batch_max: int,
        flush_interval: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._buffer = buffer
        self._url = url
        self._token = token
        self._batch_max = batch_max
        self._flush_interval = flush_interval
        self._transport = transport

    async def _post(self, batch: list[OutboundPayload]) -> None:
        body = {
            "payload_version": "1",
            "signatures": [p.model_dump(mode="json") for p in batch],
        }
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        for attempt in range(MAX_ATTEMPTS):
            try:
                async with httpx.AsyncClient(timeout=10.0, transport=self._transport) as client:
                    response = await client.post(self._url, json=body, headers=headers)
                    response.raise_for_status()
                record_outbound_sent(len(batch))
                return
            except Exception as exc:  # network, status, timeout: retry then drop
                if attempt + 1 < MAX_ATTEMPTS:
                    await asyncio.sleep(BACKOFF_BASE * (2**attempt))
                    continue
                _log.warning("signature_outbound_post_failed", error=exc.__class__.__name__)
                record_outbound_failed(len(batch))

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval)
            batch = self._buffer.drain(self._batch_max)
            if batch:
                await self._post(batch)


def build_outbound_shipper(
    settings: TerminusSettings, buffer: OutboundBuffer
) -> OutboundShipper | None:
    """Construct a shipper when outbound is enabled and a URL is configured."""
    if not settings.signature_outbound_enabled or not settings.signature_hub_ingest_url:
        return None
    return OutboundShipper(
        buffer=buffer,
        url=settings.signature_hub_ingest_url,
        token=settings.signature_hub_token,
        batch_max=settings.signature_outbound_batch_max,
        flush_interval=settings.signature_outbound_flush_interval,
    )
