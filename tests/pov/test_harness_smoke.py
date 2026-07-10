"""Smoke test: the harness runs end to end in-process and gates correctly."""

from __future__ import annotations

from pathlib import Path

from pov.harness import run_in_process


def test_harness_runs_and_passes_on_real_corpus(tmp_path: Path) -> None:
    # Runs functional + audit + in-process latency against the bundled app and
    # corpus, skipping the deployed-load pass (no server). Returns a RunResult.
    result = run_in_process(out_dir=tmp_path)
    failures = result.gate()
    assert failures == [], f"PoV gate failed: {failures}"
    assert (tmp_path / "pov_report.md").exists()


def test_harness_gate_catches_a_broken_expectation(tmp_path: Path) -> None:
    # A corpus whose single entry expects the wrong decision must fail the gate
    # (proves the gate is wired, not vacuous).
    from pov.models import CorpusEntry

    bad = [
        CorpusEntry(
            id="bad",
            sql="DROP TABLE public.users",
            category="destructive_ddl",
            expected_decision="allow",
        )
    ]
    result = run_in_process(out_dir=tmp_path, entries=bad)
    # The DROP is correctly denied, but it was tagged allow, so decision_correct is False
    # and it is a dangerous category that was blocked -> safety still 100%, but the
    # mis-tag surfaces as a decision mismatch in the outcomes.
    assert any(not o.decision_correct for o in result.outcomes)
    assert result.gate() != [], "gate must fail when an entry's decision does not match its tag"
