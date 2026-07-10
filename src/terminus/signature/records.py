"""Signature records and signed-bundle models for the intelligence subsystem.

These are name-free by construction (same privacy ceiling as Phase 1): a record
carries the abstracted query_fingerprint plus action/explainability metadata only.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SUPPORTED_BUNDLE_FORMAT_VERSIONS: frozenset[str] = frozenset({"1"})

Severity = Literal["low", "medium", "high", "critical"]
Mode = Literal["observe", "enforce"]
Source = Literal["bundle", "local"]


class SignatureRecord(BaseModel):
    """One known-bad signature. query_fingerprint is the match key; signature_id
    is the human/ops handle (pin, disable, provenance, dedup)."""

    model_config = ConfigDict(extra="forbid")

    signature_id: str
    query_fingerprint: str
    fingerprint_version: str
    technique: str | None = None
    severity: Severity
    mode: Mode
    description: str = ""
    first_seen: str = ""
    source: Source = "bundle"


class SignatureBundle(BaseModel):
    """A versioned set of signatures. The verified body of a signed bundle."""

    model_config = ConfigDict(extra="forbid")

    bundle_format_version: str
    fingerprint_version: str
    bundle_id: str
    issued_at: str
    signing_key_id: str | None = None
    signatures: list[SignatureRecord] = Field(default_factory=list)
