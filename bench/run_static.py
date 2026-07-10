"""Static corpus runner: score a tagged corpus into a confusion-matrix scorecard.

Reuses the shipped decision path through FastAPI TestClient (mirrors
pov/harness.py exactly, not a direct engine call) so the number reflects the
real request pipeline: authenticate -> rate limit -> parse -> policy ->
signature/velocity -> remediation. Headlines the benign false-positive rate;
dangerous-recall is reported but demoted (spec section 3).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import BaseModel

from bench.score import ConfusionMatrix, confusion_matrix, false_positive_rate, youden_j
from pov.functional import run_functional
from pov.loader import load_corpus
from pov.models import CorpusEntry
from terminus.main import app

_BENIGN = frozenset({"benign_read", "benign_write"})

_POV_CORPUS = Path(__file__).resolve().parent.parent / "pov" / "corpus.yaml"
_BENIGN_CORPUS = Path(__file__).resolve().parent / "corpus_benign.yaml"
_OUT_PATH = Path(__file__).resolve().parent / "out" / "static_scorecard.json"


class StaticReport(BaseModel):
    total: int
    confusion: ConfusionMatrix
    false_positive_rate: float
    youden_j: float
    dangerous_blocked_rate: float
    benign_false_positives: int


def score_entries(rows: Sequence[tuple[str, str, bool]]) -> StaticReport:
    """rows: (expected_decision, actual_decision, is_attack)."""
    scored = [(actual == "deny", is_attack) for _expected, actual, is_attack in rows]
    cm = confusion_matrix(scored)
    dangerous = cm.tp + cm.fn
    return StaticReport(
        total=len(rows),
        confusion=cm,
        false_positive_rate=false_positive_rate(scored),
        youden_j=youden_j(scored),
        dangerous_blocked_rate=cm.tp / dangerous if dangerous else 1.0,
        benign_false_positives=cm.fp,
    )


def load_merged_corpus() -> list[CorpusEntry]:
    """The PoV corpus (benign + dangerous) plus the extra benign traffic corpus
    that exists specifically to size the benign-FPR sample (spec section 3)."""
    return load_corpus(_POV_CORPUS) + load_corpus(_BENIGN_CORPUS)


def run_static(entries: Sequence[CorpusEntry] | None = None) -> StaticReport:
    """Run every entry through /intercept (in-process TestClient, same as the
    PoV harness) and score the resulting confusion matrix."""
    corpus = list(entries) if entries is not None else load_merged_corpus()

    with TestClient(app) as client:
        outcomes = run_functional(client, corpus)

    rows = [(o.expected_decision, o.actual_decision, o.category not in _BENIGN) for o in outcomes]
    return score_entries(rows)


def main() -> int:
    report = run_static()

    print("Static corpus scorecard")
    print(f"  total entries:          {report.total}")
    print(f"  confusion matrix:       {report.confusion.model_dump()}")
    print(f"  benign false positives: {report.benign_false_positives}")
    print(f"  benign FPR:             {report.false_positive_rate:.4%}")
    print(f"  youden J:               {report.youden_j:.4f}")
    print(f"  dangerous blocked rate: {report.dangerous_blocked_rate:.4%}")

    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUT_PATH.write_text(json.dumps(report.model_dump(), indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {_OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
