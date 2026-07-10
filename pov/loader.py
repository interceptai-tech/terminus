"""Load and validate the tagged SQL corpus."""

from __future__ import annotations

from pathlib import Path

import yaml

from pov.models import CorpusEntry

VALID_CATEGORIES: frozenset[str] = frozenset(
    {
        "benign_read",
        "benign_write",
        "destructive_ddl",
        "dangerous_dml",
        "injection",
        "hallucination",
        "column_violation",
        "multi_statement",
        "invalid_sql",
    }
)


def load_corpus(path: str | Path) -> list[CorpusEntry]:
    """Load corpus.yaml into validated entries, failing loudly on a bad corpus.

    Raises ValueError on a duplicate id or an unknown category so a malformed
    corpus never silently degrades the run.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or []
    entries = [CorpusEntry.model_validate(item) for item in raw]

    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            raise ValueError(f"duplicate corpus id: {entry.id}")
        seen.add(entry.id)
        if entry.category not in VALID_CATEGORIES:
            raise ValueError(f"unknown category {entry.category!r} on entry {entry.id}")
    return entries
