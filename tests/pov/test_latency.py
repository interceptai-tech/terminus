"""Tests for latency measurement helpers."""

from __future__ import annotations

from pov.latency import in_process_latency, percentiles
from pov.models import CorpusEntry


def test_percentiles_basic() -> None:
    stats = percentiles("x", [float(n) for n in range(1, 101)])  # 1..100 ms
    assert stats.samples == 100
    assert stats.p50_ms == 50.0
    assert stats.p99_ms == 99.0
    assert stats.max_ms == 100.0


def test_in_process_latency_runs_and_is_fast() -> None:
    entries = [
        CorpusEntry(
            id="a",
            sql="SELECT id FROM public.users WHERE id = 1",
            category="benign_read",
            expected_decision="allow",
        ),
        CorpusEntry(
            id="b",
            sql="DROP TABLE public.users",
            category="destructive_ddl",
            expected_decision="deny",
        ),
    ]
    stats = in_process_latency(entries, iterations=50)
    assert stats.samples == 100  # 2 entries x 50 iterations
    assert stats.p99_ms < 2.0  # the headline criterion, with comfortable headroom
