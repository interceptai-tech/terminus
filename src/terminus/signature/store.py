"""In-memory known-bad signature store, keyed by query_fingerprint.

Loaded like the policy/whitelist (parsed into memory, never a per-query disk hit).
swap() replaces the active map atomically; the store is never emptied by a failed
update because the Update Client only calls swap() after a successful verified load.
"""

from __future__ import annotations

from functools import lru_cache

from terminus.signature.records import SignatureRecord


class SignatureStore:
    def __init__(self) -> None:
        self._by_fingerprint: dict[str, SignatureRecord] = {}

    def lookup(self, fingerprint: str) -> SignatureRecord | None:
        return self._by_fingerprint.get(fingerprint)

    def swap(self, records: list[SignatureRecord]) -> None:
        """Atomically replace the active set. Build fully, then reassign the
        reference so the hot path never sees a half-updated map."""
        new_map = {record.query_fingerprint: record for record in records}
        self._by_fingerprint = new_map

    def __len__(self) -> int:
        return len(self._by_fingerprint)


@lru_cache(maxsize=1)
def get_signature_store() -> SignatureStore:
    """Process-wide singleton store (warmed by the Update Client at startup)."""
    return SignatureStore()
