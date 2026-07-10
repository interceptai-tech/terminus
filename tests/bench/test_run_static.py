"""Static runner scores a corpus into a confusion-matrix scorecard."""

from __future__ import annotations

from bench.run_static import score_entries


def test_score_entries_produces_fpr_and_youden() -> None:
    # (expected_decision, actual_decision, is_attack)
    rows = [
        ("deny", "deny", True),  # TP
        ("allow", "allow", False),  # TN
        ("allow", "deny", False),  # FP: benign wrongly denied
    ]
    report = score_entries(rows)
    assert report.false_positive_rate == 1 / 2  # 1 benign denied of 2 benign
    assert report.total == 3
    assert report.benign_false_positives == 1
