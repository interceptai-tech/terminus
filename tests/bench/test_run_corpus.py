"""Independent-ground-truth differential oracle for a third-party SQLi corpus.

Deterministic, no network: unit-tests the independent ground-truth labeler and
the confusion-matrix aggregation, plus the retained executed_rate helper.
"""

from __future__ import annotations

from bench.run_corpus import (
    GT_ALLOW,
    GT_DENY,
    aggregate,
    executed_rate,
    ground_truth,
)


def test_executed_rate_is_allowed_over_total() -> None:
    decisions = ["deny", "deny", "deny", "allow"]  # 1 of 4 would execute
    assert executed_rate(decisions) == 1 / 4


def test_executed_rate_all_denied_is_zero() -> None:
    assert executed_rate(["deny", "deny"]) == 0.0


# --- ground_truth labeler (independent of terminus.policy) -------------------


def test_ground_truth_off_whitelist_table_is_deny() -> None:
    # secret_table is not on examples/schema_whitelist.yaml
    assert ground_truth("SELECT id FROM secret_table") == GT_DENY


def test_ground_truth_restricted_column_is_deny() -> None:
    # public.users is restricted to [id, name, email]; passwd is off-allowlist
    assert ground_truth("SELECT passwd FROM public.users") == GT_DENY


def test_ground_truth_wildcard_over_restricted_table_is_deny() -> None:
    assert ground_truth("SELECT * FROM public.users") == GT_DENY


def test_ground_truth_multi_statement_is_deny() -> None:
    assert ground_truth("SELECT id FROM public.users; DROP TABLE public.users") == GT_DENY


def test_ground_truth_non_select_is_deny() -> None:
    assert ground_truth("DELETE FROM public.users WHERE id = 1") == GT_DENY


def test_ground_truth_injection_function_is_deny() -> None:
    assert ground_truth("SELECT id FROM public.users WHERE id = pg_sleep(5)") == GT_DENY


def test_ground_truth_unparseable_is_deny() -> None:
    # unbalanced quote from a broken string-context injection
    assert ground_truth("SELECT id FROM public.users WHERE name = '") == GT_DENY


def test_ground_truth_valid_in_scope_select_is_allow() -> None:
    assert ground_truth("SELECT id, name FROM public.users WHERE id = 5") == GT_ALLOW


def test_ground_truth_in_scope_tautology_is_allow() -> None:
    # a tautology that stays in scope is allowed by design: Terminus enforces
    # scope, not intent. The oracle labels it GT_ALLOW honestly.
    assert ground_truth("SELECT id, name FROM public.users WHERE id = 1 OR 1 = 1") == GT_ALLOW


def test_ground_truth_unrestricted_table_wildcard_is_allow() -> None:
    # public.orders has no column allowlist, so a wildcard is in scope.
    assert ground_truth("SELECT * FROM public.orders") == GT_ALLOW


# --- confusion-matrix aggregation --------------------------------------------


def test_aggregate_counts_false_allows_and_rates() -> None:
    rows = [
        (GT_DENY, "deny"),  # contained
        (GT_DENY, "deny"),  # contained
        (GT_DENY, "allow"),  # FALSE ALLOW (a leak)
        (GT_DENY, "error"),  # gt_deny error
        (GT_ALLOW, "allow"),  # in-scope allow (expected)
        (GT_ALLOW, "deny"),  # in-scope over-block (safe)
    ]
    m = aggregate(rows)
    assert m.total == 6
    assert m.gt_deny_total == 4
    assert m.gt_allow_total == 2
    assert m.contained == 2
    assert m.false_allows == 1
    assert m.gt_deny_errors == 1
    assert m.errors == 1
    assert m.in_scope_allows == 1
    assert m.in_scope_denies == 1
    assert m.containment_rate == 2 / 4
    assert m.in_scope_allow_rate == 1 / 2


def test_aggregate_clean_sweep_is_full_containment_zero_false_allows() -> None:
    rows = [(GT_DENY, "deny"), (GT_DENY, "deny"), (GT_ALLOW, "allow")]
    m = aggregate(rows)
    assert m.false_allows == 0
    assert m.errors == 0
    assert m.containment_rate == 1.0
    assert m.in_scope_allow_rate == 1.0
