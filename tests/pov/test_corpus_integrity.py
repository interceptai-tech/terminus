"""The shipped corpus loads, is internally consistent, and is well-populated."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from pov.loader import VALID_CATEGORIES, load_corpus

CORPUS = Path(__file__).resolve().parents[2] / "pov" / "corpus.yaml"

_MINIMUMS = {
    "benign_read": 40,
    "benign_write": 15,
    "destructive_ddl": 25,
    "dangerous_dml": 25,
    "injection": 30,
    "hallucination": 25,
    "column_violation": 25,
    "multi_statement": 10,
    "invalid_sql": 10,
}


def test_corpus_loads() -> None:
    entries = load_corpus(CORPUS)
    assert len(entries) >= 230


def test_category_minimums_met() -> None:
    counts = Counter(e.category for e in load_corpus(CORPUS))
    for category, minimum in _MINIMUMS.items():
        assert counts[category] >= minimum, f"{category}: {counts[category]} < {minimum}"
    assert set(counts) <= VALID_CATEGORIES


def test_self_correctable_only_on_correctable_categories() -> None:
    for e in load_corpus(CORPUS):
        if e.self_correctable:
            assert e.category in {"column_violation", "dangerous_dml"}, e.id


def test_benign_entries_are_allow_others_are_deny() -> None:
    for e in load_corpus(CORPUS):
        if e.category in {"benign_read", "benign_write"}:
            assert e.expected_decision == "allow", e.id
        else:
            assert e.expected_decision == "deny", e.id


def test_no_duplicate_sql() -> None:
    counts = Counter(e.sql.strip() for e in load_corpus(CORPUS))
    dupes = {s: n for s, n in counts.items() if n > 1}
    assert not dupes, f"duplicate SQL in corpus: {list(dupes)[:3]}"


def test_parse_cap_exceeds_corpus_max_sql() -> None:
    # The parse size cap must stay above the largest corpus entry, or the harness
    # would reject its own tagged queries as oversize and the gate would break.
    from terminus.parser.sql_parser import MAX_SQL_LENGTH

    entries = load_corpus(CORPUS)
    assert max(len(e.sql) for e in entries) < MAX_SQL_LENGTH
