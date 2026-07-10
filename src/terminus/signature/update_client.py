"""Pull, verify, resolve, and atomically swap signed signature bundles.

Runs OFF the request path. Any failure (fetch, signature, parse, format) is loud
but safe: log at ERROR, keep last-known-good, never apply unverified data.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urlparse

import httpx
import structlog

from terminus.config.settings import TerminusSettings
from terminus.observability.metrics import (
    record_signature_bundle_update_failed,
    record_version_skew,
)
from terminus.signature.overrides import load_overrides, resolve_active_records
from terminus.signature.records import SignatureRecord
from terminus.signature.signature import FINGERPRINT_VERSION
from terminus.signature.store import SignatureStore
from terminus.signature.verify import load_public_key, parse_signed_bundle

_log = structlog.get_logger("terminus.signature.update")


class SignatureUpdateClient:
    """Fetches, verifies, and atomically swaps a signed signature bundle into the store.

    Think of this like a config management agent: it pulls a signed config bundle
    from a source (URL or local file), validates the signature, filters compatible
    records, and atomically swaps the in-memory store. On any failure it keeps
    the last known good state, just like how a config management tool rolls back.
    """

    def __init__(
        self,
        *,
        source: str,
        public_key_value: str,
        store: SignatureStore,
        overrides_path: str,
    ) -> None:
        self.source = source
        self.store = store
        self._overrides_path = overrides_path
        self._public_key = load_public_key(public_key_value)

    async def _fetch(self) -> bytes:
        """Fetch the raw bundle bytes from the configured source.

        Like a config pull: supports HTTP(S) remote sources and local file paths.
        """
        if urlparse(self.source).scheme in ("http", "https"):
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.source)
                response.raise_for_status()
                return response.content
        return Path(self.source).read_bytes()

    async def refresh(self) -> bool:
        """Fetch + verify + apply one bundle. Returns True if applied, False on any failure.

        On failure the last-known-good set is retained (the store is NEVER emptied).
        This is the fail-safe: like a firewall that keeps the last valid ruleset
        if the new one fails to parse.
        """
        try:
            raw = await self._fetch()
            bundle = parse_signed_bundle(raw, self._public_key)
            # Only keep records matching the current fingerprint algorithm version.
            # Records from a different version are incompatible (like an old config format).
            matching = [
                r for r in bundle.signatures if r.fingerprint_version == FINGERPRINT_VERSION
            ]
            record_version_skew(len(bundle.signatures) - len(matching))
            overrides = load_overrides(self._overrides_path)
            active: list[SignatureRecord] = resolve_active_records(matching, overrides)
            # Final uniform version filter: also guards operator-authored local signatures
            # in overrides whose fingerprint_version was set to a wrong value.
            active = [r for r in active if r.fingerprint_version == FINGERPRINT_VERSION]
            self.store.swap(active)
            _log.info("signature_bundle_applied", count=len(active), bundle_id=bundle.bundle_id)
            return True
        except Exception as exc:  # loud but safe: keep last-known-good
            _log.error("signature_bundle_update_failed", error=exc.__class__.__name__)
            record_signature_bundle_update_failed()
            return False


def build_update_client(
    settings: TerminusSettings, store: SignatureStore
) -> SignatureUpdateClient | None:
    """Construct a client when matching is enabled and a source is configured.

    Returns None when matching is off or no source is set; the lifespan skips
    all update logic in that case. This matches the pattern of feature flags
    controlling whether a service/daemon is even started.
    """
    if not settings.signature_matching_enabled or not settings.signature_bundle_source:
        return None
    return SignatureUpdateClient(
        source=settings.signature_bundle_source,
        public_key_value=settings.signature_bundle_public_key,
        store=store,
        overrides_path=settings.signature_overrides_path,
    )


async def run_poll_loop(client: SignatureUpdateClient, interval: int) -> None:
    """Refresh every `interval` seconds until cancelled.

    Caller starts this as a background task only when interval > 0.
    The sleep-then-refresh order means the startup warm (off the request path)
    already ran; polling is the recurring update, not the initial load.
    """
    while True:
        await asyncio.sleep(interval)
        await client.refresh()
