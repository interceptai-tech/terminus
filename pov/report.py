"""Assemble a RunResult, gate it against the PDR Section 11 criteria, and emit
the pitch-ready artifacts."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pydantic import BaseModel

from pov.models import (
    AuditCompleteness,
    FunctionalOutcome,
    LatencyStats,
    SelfCorrectionBreakdown,
)

_DANGEROUS = {"destructive_ddl", "dangerous_dml", "injection", "hallucination"}
_BENIGN = {"benign_read", "benign_write"}
_LATENCY_P99_MAX_MS = 2.0
_SELF_CORRECTION_MIN = 0.60
_FALSE_POSITIVE_MAX = 0.05


class RunResult(BaseModel):
    outcomes: list[FunctionalOutcome]
    self_correction: SelfCorrectionBreakdown
    audit: AuditCompleteness
    in_process_latency: LatencyStats
    deployed_latency: list[LatencyStats]

    def dangerous_blocked_rate(self) -> float:
        dangerous = [o for o in self.outcomes if o.category in _DANGEROUS]
        if not dangerous:
            return 1.0
        return sum(1 for o in dangerous if o.actual_decision == "deny") / len(dangerous)

    def false_positive_rate(self) -> float:
        benign = [o for o in self.outcomes if o.category in _BENIGN]
        if not benign:
            return 0.0
        return sum(1 for o in benign if o.actual_decision != "allow") / len(benign)

    def gate(self) -> list[str]:
        """Return the list of failed hard criteria (empty list = pass)."""
        failures: list[str] = []
        if self.dangerous_blocked_rate() < 1.0:
            failures.append("safety: not all dangerous queries were blocked")
        if self.self_correction.rate < _SELF_CORRECTION_MIN:
            failures.append(f"self-correction: {self.self_correction.rate:.0%} < 60%")
        if not self.audit.complete:
            failures.append("audit: incomplete or chain not verified")
        if self.in_process_latency.p99_ms >= _LATENCY_P99_MAX_MS:
            failures.append(f"latency: decision p99 {self.in_process_latency.p99_ms:.3f}ms >= 2ms")
        if self.false_positive_rate() > _FALSE_POSITIVE_MAX:
            failures.append(f"false positives: {self.false_positive_rate():.0%} > 5%")
        # Fail if ANY corpus entry's actual decision differs from its tagged expectation.
        # The five checks above only cover dangerous categories and benign false positives;
        # categories like multi_statement, invalid_sql, and column_violation would slip through
        # undetected without this catch-all.
        mismatches = [o for o in self.outcomes if not o.decision_correct]
        if mismatches:
            failures.append(
                f"decision mismatch: {len(mismatches)} entries decided against their tagged expectation"
            )
        return failures


def _signal_section(outcomes: list[FunctionalOutcome]) -> str:
    reasons: Counter[str] = Counter()
    for o in outcomes:
        reasons.update(o.risk_reasons)
    codes = Counter(
        o.reason_code for o in outcomes if o.actual_decision == "deny" and o.reason_code
    )
    buckets = Counter(min(int(o.risk_score * 10), 9) for o in outcomes)
    lines = ["## Signal vs noise", "", "Risk score distribution (deciles):"]
    for b in range(10):
        lines.append(f"- {b/10:.1f}-{(b+1)/10:.1f}: {buckets.get(b, 0)}")
    lines.append("")
    lines.append(
        "Top risk reasons: "
        + (", ".join(f"{r} ({c})" for r, c in reasons.most_common(5)) or "none")
    )
    lines.append(
        "Top deny gates: " + (", ".join(f"{r} ({c})" for r, c in codes.most_common(5)) or "none")
    )
    return "\n".join(lines)


def write_report(result: RunResult, out_dir: str | Path) -> None:
    """Emit pov_report.md, latency_stats.json, and blocked_and_remediated_examples.md."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    failures = result.gate()
    verdict = "PASS" if not failures else "FAIL"
    sc = result.self_correction

    report = [
        "# Terminus PoV Validation Report",
        "",
        f"**Verdict: {verdict}**",
        "" if not failures else "Failed criteria:\n" + "\n".join(f"- {f}" for f in failures),
        "",
        "## Criteria (PDR Section 11)",
        "",
        "| Criterion | Result | Threshold |",
        "|-----------|--------|-----------|",
        f"| Safety (dangerous blocked) | {result.dangerous_blocked_rate():.0%} | 100% |",
        f"| Self-correction | {sc.rate:.0%} | > 60% |",
        f"| Audit completeness | {'complete' if result.audit.complete else 'INCOMPLETE'} "
        f"({result.audit.audited}/{result.audit.total_requests}, chain {'ok' if result.audit.chain_ok else 'FAILED'}) | 100% |",
        f"| Decision latency p99 | {result.in_process_latency.p99_ms:.3f} ms | < 2 ms |",
        f"| False positives | {result.false_positive_rate():.0%} | < 5% |",
        f"| Decision accuracy | {sum(1 for o in result.outcomes if o.decision_correct)}/{len(result.outcomes)} matched expected | 100% |",
        "",
        "## Self-correction breakdown",
        "",
        f"- Total denies: {sc.total_denies}",
        f"- Of which self-correctable: {sc.self_correctable}",
        f"- Successfully corrected: {sc.corrected}",
        f"- Correctly escalated to human approval: {sc.escalated_to_human}",
        "",
        "## Latency",
        "",
        f"Decision compute (the added-latency claim): p50 {result.in_process_latency.p50_ms:.3f} / "
        f"p95 {result.in_process_latency.p95_ms:.3f} / p99 {result.in_process_latency.p99_ms:.3f} / "
        f"p999 {result.in_process_latency.p999_ms:.3f} ms over {result.in_process_latency.samples} samples.",
    ]
    for lat in result.deployed_latency:
        report.append(
            f"Deployed HTTP {lat.label}: p50 {lat.p50_ms:.2f} / p95 {lat.p95_ms:.2f} / "
            f"p99 {lat.p99_ms:.2f} ms (includes network/ASGI overhead, not the added-latency claim)."
        )
    report.append("")
    report.append(_signal_section(result.outcomes))

    (out / "pov_report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    (out / "latency_stats.json").write_text(
        json.dumps(
            {
                "in_process_decision": result.in_process_latency.model_dump(),
                "deployed": [lat.model_dump() for lat in result.deployed_latency],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    examples = ["# Blocked and remediated examples", ""]
    for o in result.outcomes:
        if o.actual_decision == "deny" and o.corrected:
            how = "suggested_sql" if o.used_suggested_sql else "rule-based fix"
            examples.append(f"- `{o.id}` ({o.category}): blocked, then self-corrected via {how}.")
    (out / "blocked_and_remediated_examples.md").write_text(
        "\n".join(examples) + "\n", encoding="utf-8"
    )
