"""Report assembly + the pass/fail gate."""

from __future__ import annotations

from pathlib import Path

from pov.models import AuditCompleteness, FunctionalOutcome, LatencyStats, SelfCorrectionBreakdown
from pov.report import RunResult, write_report


def _good_result() -> RunResult:
    outcomes = [
        FunctionalOutcome(
            id="a",
            category="benign_read",
            expected_decision="allow",
            actual_decision="allow",
            decision_correct=True,
            reason_code=None,
            risk_score=0.1,
            risk_reasons=[],
            self_correctable=False,
        ),
        FunctionalOutcome(
            id="b",
            category="destructive_ddl",
            expected_decision="deny",
            actual_decision="deny",
            decision_correct=True,
            reason_code="policy_rule",
            risk_score=1.0,
            risk_reasons=["destructive_operation"],
            self_correctable=False,
            corrected=False,
        ),
        FunctionalOutcome(
            id="c",
            category="column_violation",
            expected_decision="deny",
            actual_decision="deny",
            decision_correct=True,
            reason_code="column_whitelist",
            risk_score=0.5,
            risk_reasons=[],
            self_correctable=True,
            corrected=True,
            used_suggested_sql=True,
        ),
    ]
    lat = LatencyStats(
        label="in_process_decision",
        samples=100,
        mean_ms=0.2,
        p50_ms=0.2,
        p95_ms=0.4,
        p99_ms=0.5,
        p999_ms=1.0,
        max_ms=2.0,
    )
    return RunResult(
        outcomes=outcomes,
        self_correction=SelfCorrectionBreakdown(
            total_denies=2, self_correctable=1, corrected=1, escalated_to_human=1
        ),
        audit=AuditCompleteness(
            total_requests=3, audited=3, verified_count=3, chain_ok=True, failures=[]
        ),
        in_process_latency=lat,
        deployed_latency=[],
    )


def test_gate_passes_on_good_result() -> None:
    assert _good_result().gate() == []


def test_gate_fails_on_dangerous_allowed() -> None:
    result = _good_result()
    result.outcomes[1].actual_decision = "allow"  # a DROP was allowed
    result.outcomes[1].decision_correct = False
    failures = result.gate()
    assert any("safety" in f.lower() or "dangerous" in f.lower() for f in failures)


def test_gate_fails_on_latency_regression() -> None:
    result = _good_result()
    result.in_process_latency.p99_ms = 3.0
    assert any("latency" in f.lower() for f in result.gate())


def test_gate_fails_on_decision_mismatch() -> None:
    result = _good_result()
    # A column_violation that Terminus wrongly allowed: it is not in _DANGEROUS (so
    # dangerous_blocked_rate stays 100%) and not in _BENIGN (so false_positive_rate is
    # unaffected). Without the decision-mismatch clause this would silently exit 0.
    result.outcomes.append(
        FunctionalOutcome(
            id="leak",
            category="column_violation",
            expected_decision="deny",
            actual_decision="allow",
            decision_correct=False,
            reason_code=None,
            risk_score=0.5,
            risk_reasons=[],
            self_correctable=False,
        )
    )
    assert any("decision mismatch" in f for f in result.gate())


def test_write_report_emits_artifacts(tmp_path: Path) -> None:
    write_report(_good_result(), tmp_path)
    report = (tmp_path / "pov_report.md").read_text(encoding="utf-8")
    assert "Self-correction" in report
    assert "escalated to human" in report.lower()
    assert (tmp_path / "latency_stats.json").exists()
    assert (tmp_path / "blocked_and_remediated_examples.md").exists()
