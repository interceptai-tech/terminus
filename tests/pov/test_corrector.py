"""Tests for the rule-based corrector (the non-suggested_sql self-correction path)."""

from __future__ import annotations

from pov.corrector import rule_based_correct


def test_update_without_where_gets_where() -> None:
    fixed = rule_based_correct("UPDATE public.users SET name = 'x'", "postgres")
    assert fixed is not None
    assert "where" in fixed.lower()


def test_update_with_where_is_not_changed() -> None:
    assert rule_based_correct("UPDATE public.users SET name = 'x' WHERE id = 1", "postgres") is None


def test_drop_is_not_correctable() -> None:
    assert rule_based_correct("DROP TABLE public.users", "postgres") is None


def test_select_is_not_correctable() -> None:
    assert rule_based_correct("SELECT * FROM public.users", "postgres") is None
