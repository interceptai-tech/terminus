"""Counters for previously log-only failure signals: rate-limiter health and
inbound signature-bundle update failures."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from terminus.observability import metrics


def _val(counter: Any) -> float:
    return counter._value.get()


def test_record_helpers_increment() -> None:
    before = _val(metrics.RATE_LIMITER_UNAVAILABLE_TOTAL)
    metrics.record_rate_limiter_unavailable()
    assert _val(metrics.RATE_LIMITER_UNAVAILABLE_TOTAL) == before + 1

    before = _val(metrics.SIGNATURE_BUNDLE_UPDATE_FAILED_TOTAL)
    metrics.record_signature_bundle_update_failed()
    assert _val(metrics.SIGNATURE_BUNDLE_UPDATE_FAILED_TOTAL) == before + 1


def test_rate_limit_skipped_increments_counter() -> None:
    # In-process there is no Redis, so enforce_rate_limit logs rate_limit_skipped
    # and must increment the rate-limiter counter. A /intercept request (plus the
    # lifespan's failed Redis init) exercises that path.
    from terminus.main import app

    before = _val(metrics.RATE_LIMITER_UNAVAILABLE_TOTAL)
    with TestClient(app) as client:
        client.post(
            "/intercept",
            json={
                "sql": "SELECT id FROM public.users WHERE id = 1",
                "agent_id": "analytics_agent_42",
            },
        )
    assert _val(metrics.RATE_LIMITER_UNAVAILABLE_TOTAL) > before


async def test_bundle_update_failure_increments_counter(tmp_path: Any) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from terminus.signature.store import get_signature_store
    from terminus.signature.update_client import SignatureUpdateClient

    # A valid public key (so construction succeeds) but a missing source file, so
    # refresh() fails at fetch and hits the except branch that records the failure.
    pub_pem = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    before = _val(metrics.SIGNATURE_BUNDLE_UPDATE_FAILED_TOTAL)
    client = SignatureUpdateClient(
        source=str(tmp_path / "does-not-exist.json"),
        public_key_value=pub_pem,
        store=get_signature_store(),
        overrides_path="",
    )
    applied = await client.refresh()
    assert applied is False
    assert _val(metrics.SIGNATURE_BUNDLE_UPDATE_FAILED_TOTAL) == before + 1
