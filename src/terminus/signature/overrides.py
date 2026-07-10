"""Local override resolution. Local always wins over bundle defaults."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from terminus.signature.records import SignatureRecord


class SignatureOverrides(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disable: list[str] = Field(default_factory=list)  # signature_ids to drop
    mode: dict[str, str] = Field(default_factory=dict)  # signature_id -> "observe"|"enforce"
    signatures: list[SignatureRecord] = Field(default_factory=list)  # local-authored


def load_overrides(path: str) -> SignatureOverrides:
    """Load the overrides file. Empty (no-op) when path is unset or missing."""
    if not path:
        return SignatureOverrides()
    file = Path(path)
    if not file.exists():
        return SignatureOverrides()
    data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    return SignatureOverrides.model_validate(data)


def resolve_active_records(
    bundle_records: list[SignatureRecord], overrides: SignatureOverrides
) -> list[SignatureRecord]:
    """Apply precedence: drop disabled ids, apply mode overrides, add local
    signatures (which also respect disable). Local always wins."""
    disabled = set(overrides.disable)
    merged: list[SignatureRecord] = list(bundle_records)
    # local-authored signatures are appended; bundles never remove them
    merged.extend(record.model_copy(update={"source": "local"}) for record in overrides.signatures)

    result: list[SignatureRecord] = []
    for record in merged:
        if record.signature_id in disabled:
            continue
        new_mode = overrides.mode.get(record.signature_id)
        result.append(record.model_copy(update={"mode": new_mode}) if new_mode else record)
    return result
