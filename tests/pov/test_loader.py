"""Tests for the corpus loader and schema."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from pov.loader import VALID_CATEGORIES, load_corpus


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "corpus.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def test_loads_valid_corpus(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        - id: ok_read
          sql: "SELECT id FROM public.users WHERE id = 1"
          category: benign_read
          expected_decision: allow
        - id: drop_users
          sql: "DROP TABLE public.users"
          category: destructive_ddl
          expected_decision: deny
          expected_reason_code: policy_rule
          self_correctable: false
        """,
    )
    entries = load_corpus(path)
    assert len(entries) == 2
    assert entries[0].id == "ok_read"
    assert entries[0].self_correctable is False  # default
    assert entries[1].expected_reason_code == "policy_rule"


def test_duplicate_id_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        - id: dup
          sql: "SELECT 1"
          category: benign_read
          expected_decision: allow
        - id: dup
          sql: "SELECT 2"
          category: benign_read
          expected_decision: allow
        """,
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_corpus(path)


def test_unknown_category_raises(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        - id: x
          sql: "SELECT 1"
          category: not_a_category
          expected_decision: allow
        """,
    )
    with pytest.raises(ValueError, match="category"):
        load_corpus(path)


def test_valid_categories_constant_is_frozen() -> None:
    assert "benign_read" in VALID_CATEGORIES
    assert "column_violation" in VALID_CATEGORIES
