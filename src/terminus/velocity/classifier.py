"""Name-free classifier: is a query an extraction-oracle probe, and under what key."""

from __future__ import annotations

from terminus.signature.facts import SignatureFacts


def extraction_class(facts: SignatureFacts, fingerprint: str) -> str | None:
    """Return the velocity class key for an extraction-shaped read, else None.

    Only a SELECT carrying a WHERE predicate can be an oracle probe: enumeration
    (WHERE id = 1, 2, 3, ...) and binary-search (WHERE col < X, repeated) both vary
    a predicate literal across many reads. A WHERE-less scan is a single bulk read,
    not a sequence; writes and DDL are handled by other gates and are not oracles.

    The key is the already-computed, name-free ``fingerprint`` (query_fingerprint).
    Because literals are stripped, all the varying-literal probes collapse into one
    bucket, so per-key velocity is exactly the enumeration / binary-search signal.
    """
    if facts.operation != "SELECT" or not facts.has_where:
        return None
    return fingerprint
