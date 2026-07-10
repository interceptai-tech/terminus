"""Shared types for the PoV validation harness."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class CorpusEntry(BaseModel):
    """One tagged query in the validation corpus.

    expected_decision is defined against the shipped example policy + whitelist.
    self_correctable marks denies a corrected query should be able to pass (it
    drives the self-correction rate denominator); destructive ops are False.
    """

    id: str
    sql: str
    dialect: str | None = None
    category: str
    expected_decision: Literal["allow", "deny"]
    expected_reason_code: str | None = None
    self_correctable: bool = False


class LatencyStats(BaseModel):
    """Percentile summary for one latency measurement."""

    label: str
    samples: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    p999_ms: float
    max_ms: float


class FunctionalOutcome(BaseModel):
    """Result of running one corpus entry through /intercept."""

    id: str
    category: str
    expected_decision: str
    actual_decision: str
    decision_correct: bool
    reason_code: str | None
    risk_score: float
    risk_reasons: list[str]
    self_correctable: bool
    corrected: bool | None = None  # None when not a deny / not attempted
    used_suggested_sql: bool = False


class SelfCorrectionBreakdown(BaseModel):
    """Transparent self-correction tally for the report."""

    total_denies: int
    self_correctable: int
    corrected: int
    escalated_to_human: int  # denies correctly requiring approval (not failures)

    @property
    def rate(self) -> float:
        return self.corrected / self.self_correctable if self.self_correctable else 1.0


class AuditCompleteness(BaseModel):
    """Audit-stream completeness + chain verification result."""

    total_requests: int
    audited: int
    verified_count: int
    chain_ok: bool
    failures: list[str]

    @property
    def complete(self) -> bool:
        return self.audited == self.total_requests and self.chain_ok
