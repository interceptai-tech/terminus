"""Update Client: verified load applies; failure keeps last-known-good; skew skips."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from terminus.signature.records import SignatureRecord
from terminus.signature.store import SignatureStore
from terminus.signature.update_client import (
    SignatureUpdateClient,
    build_update_client,
    run_poll_loop,
)
from terminus.signature.verify import canonical_body


def _write_signed_bundle(path: object, priv: Ed25519PrivateKey, records: list[dict]) -> None:  # type: ignore[type-arg]
    body = {
        "bundle_format_version": "1",
        "fingerprint_version": "1",
        "bundle_id": "b1",
        "issued_at": "2026-06-25T00:00:00Z",
        "signatures": records,
    }
    sig = priv.sign(canonical_body(body))
    import pathlib

    pathlib.Path(str(path)).write_text(
        json.dumps({"bundle": body, "signature": base64.b64encode(sig).decode()})
    )


def _rec(sid: str, fp: str, fpv: str = "1") -> dict:  # type: ignore[type-arg]
    return {
        "signature_id": sid,
        "query_fingerprint": fp,
        "fingerprint_version": fpv,
        "severity": "high",
        "mode": "observe",
    }


def _client(source: object, pub: str, overrides_path: str = "") -> SignatureUpdateClient:
    return SignatureUpdateClient(
        source=str(source),
        public_key_value=pub,
        store=SignatureStore(),
        overrides_path=overrides_path,
    )


@pytest.mark.asyncio
async def test_verified_bundle_applies(tmp_path) -> None:  # type: ignore[no-untyped-def]
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    bundle = tmp_path / "bundle.json"
    _write_signed_bundle(bundle, priv, [_rec("sig-1", "fp1")])
    client = _client(bundle, pub)
    assert await client.refresh() is True
    assert client.store.lookup("fp1") is not None


@pytest.mark.asyncio
async def test_bad_signature_keeps_last_known_good(tmp_path) -> None:  # type: ignore[no-untyped-def]
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    pub_other = base64.b64encode(other.public_key().public_bytes_raw()).decode()
    bundle = tmp_path / "bundle.json"
    _write_signed_bundle(bundle, priv, [_rec("sig-1", "fp1")])  # signed by priv, verified by other
    client = _client(bundle, pub_other)
    client.store.swap(
        [
            SignatureRecord(
                signature_id="prev",
                query_fingerprint="prev-fp",
                fingerprint_version="1",
                severity="low",
                mode="observe",
            )
        ]
    )
    assert await client.refresh() is False  # rejected
    assert client.store.lookup("prev-fp") is not None  # previous set retained
    assert client.store.lookup("fp1") is None


@pytest.mark.asyncio
async def test_version_skew_is_skipped(tmp_path) -> None:  # type: ignore[no-untyped-def]
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    bundle = tmp_path / "bundle.json"
    _write_signed_bundle(bundle, priv, [_rec("sig-1", "fp1", "1"), _rec("sig-2", "fp2", "999")])
    client = _client(bundle, pub)
    assert await client.refresh() is True
    assert client.store.lookup("fp1") is not None  # matching version kept
    assert client.store.lookup("fp2") is None  # skewed version skipped


@pytest.mark.asyncio
async def test_build_update_client_none_when_disabled(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """build_update_client returns None when matching is off or source is empty."""
    from terminus.config.settings import TerminusSettings

    # matching disabled
    settings = TerminusSettings(signature_matching_enabled=False, signature_bundle_source="x")
    store = SignatureStore()
    assert build_update_client(settings, store) is None

    # matching enabled but no source
    settings2 = TerminusSettings(signature_matching_enabled=True, signature_bundle_source="")
    assert build_update_client(settings2, store) is None


@pytest.mark.asyncio
async def test_build_update_client_returns_client_when_configured(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """build_update_client returns a SignatureUpdateClient when properly configured."""
    from terminus.config.settings import TerminusSettings

    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    bundle = tmp_path / "bundle.json"
    _write_signed_bundle(bundle, priv, [_rec("sig-1", "fp1")])

    settings = TerminusSettings(
        signature_matching_enabled=True,
        signature_bundle_source=str(bundle),
        signature_bundle_public_key=pub,
    )
    store = SignatureStore()
    client = build_update_client(settings, store)
    assert client is not None
    assert isinstance(client, SignatureUpdateClient)


@pytest.mark.asyncio
async def test_poll_loop_calls_refresh(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """run_poll_loop refreshes the client until cancelled."""
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    bundle = tmp_path / "bundle.json"
    _write_signed_bundle(bundle, priv, [_rec("sig-1", "fp1")])

    client = _client(bundle, pub)
    task = asyncio.create_task(run_poll_loop(client, interval=0))
    # Let the loop tick at least once (interval=0 means sleep(0) then refresh)
    await asyncio.sleep(0.05)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    # At least one refresh happened: fp1 should be in the store
    assert client.store.lookup("fp1") is not None


@pytest.mark.asyncio
async def test_local_override_wrong_fingerprint_version_is_excluded(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A local-authored override with fingerprint_version != FINGERPRINT_VERSION must NOT enter the store.

    This exercises the final uniform version filter added after resolve_active_records.
    The bundle contributes one valid record (fp1, version="1"). The overrides file
    contributes one local-authored record (fp-local-bad, version="999"). After refresh(),
    fp1 must be present and fp-local-bad must be absent.
    """
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    bundle = tmp_path / "bundle.json"
    _write_signed_bundle(bundle, priv, [_rec("sig-good", "fp1")])

    overrides_file = tmp_path / "overrides.yaml"
    overrides_file.write_text(
        yaml.dump(
            {
                "signatures": [
                    {
                        "signature_id": "local-bad-version",
                        "query_fingerprint": "fp-local-bad",
                        "fingerprint_version": "999",
                        "severity": "high",
                        "mode": "observe",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    client = _client(bundle, pub, overrides_path=str(overrides_file))
    assert await client.refresh() is True
    assert client.store.lookup("fp1") is not None  # good bundle record present
    assert client.store.lookup("fp-local-bad") is None  # mismatched local record excluded
