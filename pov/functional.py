"""Functional pass: send each corpus entry through /intercept, check the decision,
and on a deny attempt self-correction (suggested_sql first, then rule-based)."""

from __future__ import annotations

import random
from collections.abc import Sequence
from typing import Any, Protocol, cast

from pov.corrector import rule_based_correct
from pov.models import CorpusEntry, FunctionalOutcome, SelfCorrectionBreakdown

_AGENT_ID = "analytics_agent_42"


class _Client(Protocol):
    def post(self, url: str, *, json: dict[str, Any]) -> Any: ...


def _decision(response: Any) -> str:
    """Extract the decision, treating any response without one (an error, a 429,
    a 422) as a deny: the safe default for a circuit-breaker validation tool."""
    return cast(str, response.json().get("decision", "deny"))


def _intercept(
    client: _Client, sql: str, dialect: str | None, request_id: str | None = None
) -> Any:
    payload: dict[str, Any] = {"sql": sql, "dialect": dialect, "agent_id": _AGENT_ID}
    if request_id is not None:
        payload["request_id"] = request_id
    return client.post("/intercept", json=payload)


def run_functional(
    client: _Client, entries: Sequence[CorpusEntry], *, seed: int = 1337
) -> list[FunctionalOutcome]:
    """Run every entry through /intercept in a fixed-seed shuffled order.

    The shuffle (deterministic via the seed) guards against ordering/caching
    artifacts; per-entry assertions are order-independent.
    """
    order = list(entries)
    random.Random(seed).shuffle(order)

    outcomes: list[FunctionalOutcome] = []
    for entry in order:
        resp = _intercept(client, entry.sql, entry.dialect, request_id=entry.id)
        body = resp.json()
        actual = _decision(resp)
        corrected: bool | None = None
        used_suggested = False

        if actual == "deny":
            corrected = False
            remediation = body.get("remediation") or {}
            suggested = remediation.get("suggested_sql")
            if suggested:
                retry = _intercept(client, suggested, entry.dialect)
                if _decision(retry) == "allow":
                    corrected = True
                    used_suggested = True
            if not corrected:
                fixed = rule_based_correct(entry.sql, entry.dialect)
                if (
                    fixed is not None
                    and _decision(_intercept(client, fixed, entry.dialect)) == "allow"
                ):
                    corrected = True

        outcomes.append(
            FunctionalOutcome(
                id=entry.id,
                category=entry.category,
                expected_decision=entry.expected_decision,
                actual_decision=actual,
                decision_correct=(actual == entry.expected_decision),
                reason_code=body.get("policy_id"),
                risk_score=body.get("risk_score", 0.0),
                risk_reasons=body.get("risk_reasons", []),
                self_correctable=entry.self_correctable,
                corrected=corrected,
                used_suggested_sql=used_suggested,
            )
        )
    return outcomes


def self_correction_breakdown(outcomes: Sequence[FunctionalOutcome]) -> SelfCorrectionBreakdown:
    """Tally denies into the transparent self-correction breakdown."""
    denies = [o for o in outcomes if o.actual_decision == "deny"]
    correctable = [o for o in denies if o.self_correctable]
    return SelfCorrectionBreakdown(
        total_denies=len(denies),
        self_correctable=len(correctable),
        corrected=sum(1 for o in correctable if o.corrected),
        escalated_to_human=sum(1 for o in denies if not o.self_correctable),
    )
