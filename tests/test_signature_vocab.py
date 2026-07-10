"""Controlled vocabularies and the SignatureFacts data type."""

import dataclasses

import pytest

from terminus.signature import vocab
from terminus.signature.facts import SignatureFacts


def test_vocabularies_are_frozensets() -> None:
    assert "restricted" in vocab.COLUMN_ROLES
    assert "unlisted" in vocab.TABLE_ROLES
    assert "bare" in vocab.WILDCARDS
    assert "LIKE" in vocab.PREDICATE_OPS
    assert "aggregate_oracle_probe" in vocab.TECHNIQUES
    assert "has_smuggling_pattern" in vocab.SECURITY_FLAG_NAMES
    assert "sleep(" in vocab.KNOWN_SMUGGLING_MARKERS
    assert all(
        isinstance(v, frozenset)
        for v in (
            vocab.COLUMN_ROLES,
            vocab.TABLE_ROLES,
            vocab.WILDCARDS,
            vocab.PREDICATE_OPS,
            vocab.TECHNIQUES,
            vocab.SECURITY_FLAG_NAMES,
            vocab.KNOWN_SMUGGLING_MARKERS,
        )
    )


def test_injection_function_flag_in_security_vocab() -> None:
    # A new SecurityFlags bool is dumped into signatures; it must be in the vocab or
    # the privacy guard drops every injection signature.
    assert "has_injection_function" in vocab.SECURITY_FLAG_NAMES


def test_signature_facts_is_frozen() -> None:
    facts = SignatureFacts(
        operation="SELECT",
        has_where=True,
        has_aggregate=True,
        aggregate_only=True,
        has_subquery=False,
        has_union=False,
        join_count=0,
        wildcard="none",
        predicate_ops=("LIKE",),
        projection_roles=("aggregate",),
        predicate_roles=("restricted",),
        table_roles=("restricted",),
        security_flags=(),
        smuggling_markers=(),
        risk_score=0.85,
        risk_reasons=(),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        facts.operation = "DROP"  # type: ignore[misc]
