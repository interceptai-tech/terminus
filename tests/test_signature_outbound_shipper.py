"""OutboundShipper batches + POSTs; best-effort on failure; never raises."""

import httpx
import pytest

from terminus.signature.outbound import (
    OutboundBuffer,
    OutboundShipper,
    _to_payload,
)
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


def _shipper(buffer: OutboundBuffer, handler: object, token: str = "") -> OutboundShipper:
    return OutboundShipper(
        buffer=buffer,
        url="https://hub.example/ingest",
        token=token,
        batch_max=100,
        flush_interval=30,
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_post_sends_batch_envelope_and_bearer() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content
        return httpx.Response(200)

    buf = OutboundBuffer(maxlen=10)
    await _shipper(buf, handler, token="t0ken")._post([_to_payload(_signature())])
    assert seen["auth"] == "Bearer t0ken"
    assert b'"payload_version"' in seen["body"]  # type: ignore[operator]
    assert b'"signatures"' in seen["body"]  # type: ignore[operator]


@pytest.mark.asyncio
async def test_post_failure_does_not_raise() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    buf = OutboundBuffer(maxlen=10)
    # Must complete without raising even though every attempt 500s (best-effort drop).
    await _shipper(buf, handler)._post([_to_payload(_signature())])


@pytest.mark.asyncio
async def test_no_bearer_header_when_token_empty() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200)

    buf = OutboundBuffer(maxlen=10)
    await _shipper(buf, handler, token="")._post([_to_payload(_signature())])
    assert seen["auth"] is None


def test_disabled_startup_does_not_build_buffer(monkeypatch) -> None:
    from fastapi.testclient import TestClient

    import terminus.config.settings as settings_mod
    from terminus.main import app
    from terminus.signature.outbound import get_outbound_buffer

    monkeypatch.setenv("TERMINUS_SIGNATURE_OUTBOUND_ENABLED", "false")
    settings_mod._settings = None
    get_outbound_buffer.cache_clear()
    with TestClient(app):  # triggers lifespan startup + shutdown
        pass
    assert get_outbound_buffer.cache_info().misses == 0  # buffer never constructed
    settings_mod._settings = None
    get_outbound_buffer.cache_clear()
