"""Scorer math for the security-efficacy benchmark (spec section 3)."""

from __future__ import annotations

import math

from bench.score import asr, confusion_matrix, false_positive_rate, youden_j


def test_confusion_matrix_counts() -> None:
    # (predicted_deny, is_attack) pairs
    rows = [
        (True, True),  # TP: attack, denied
        (False, True),  # FN: attack, allowed
        (True, False),  # FP: benign, denied
        (False, False),  # TN: benign, allowed
        (True, True),  # TP
    ]
    cm = confusion_matrix(rows)
    assert (cm.tp, cm.fp, cm.fn, cm.tn) == (2, 1, 1, 1)


def test_false_positive_rate_is_benign_denied_over_benign() -> None:
    rows = [(True, False), (False, False), (False, False)]  # 1 of 3 benign denied
    assert math.isclose(false_positive_rate(rows), 1 / 3)


def test_false_positive_rate_zero_benign_is_zero() -> None:
    assert false_positive_rate([(True, True)]) == 0.0


def test_youden_j_default_deny_collapses_to_benign_specificity() -> None:
    # All attacks denied (TPR=1); 1 of 4 benign wrongly denied (TNR=0.75) -> J=0.75
    rows = [
        (True, True),
        (True, True),
        (True, False),
        (False, False),
        (False, False),
        (False, False),
    ]
    assert math.isclose(youden_j(rows), 0.75)


def test_asr_counts_any_trial_success_as_success() -> None:
    # scenario -> list of per-trial "attack succeeded" bools
    per_scenario = {"s1": [False, False, True], "s2": [False, False, False]}
    # s1 succeeded (>=1 True), s2 did not -> ASR = 1/2
    assert math.isclose(asr(per_scenario), 0.5)
