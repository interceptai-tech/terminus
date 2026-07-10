"""Latency measurement: in-process decision compute (the headline <2ms claim)
and deployed HTTP round-trip under load (reported separately)."""

from __future__ import annotations

import asyncio
import statistics
import time
from collections.abc import Sequence

import httpx

from pov.models import CorpusEntry, LatencyStats
from terminus.config.settings import get_settings
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine

_AGENT_ID = "analytics_agent_42"


def percentiles(label: str, samples_ms: Sequence[float]) -> LatencyStats:
    """Summarize a list of millisecond timings."""
    ordered = sorted(samples_ms)
    n = len(ordered)

    def pct(q: float) -> float:
        if n == 0:
            return 0.0
        idx = max(0, min(n - 1, int(q * (n - 1))))
        return ordered[idx]

    return LatencyStats(
        label=label,
        samples=n,
        mean_ms=statistics.fmean(ordered) if ordered else 0.0,
        p50_ms=pct(0.50),
        p95_ms=pct(0.95),
        p99_ms=pct(0.99),
        p999_ms=pct(0.999),
        max_ms=ordered[-1] if ordered else 0.0,
    )


def in_process_latency(entries: Sequence[CorpusEntry], *, iterations: int = 20) -> LatencyStats:
    """Time the exact decision path the HTTP handler uses, with no HTTP.

    IMPORTANT: this must call parse_sql + PolicyEngine.evaluate with the same
    arguments terminus.interceptor.router.intercept uses, so it measures the same
    decision compute production does, not a different/faster path. The
    collect_signature_facts flag mirrors the router's settings-derived value.
    """
    settings = get_settings()
    collect = settings.signatures_enabled or settings.signature_matching_enabled
    engine = PolicyEngine.from_default_policy()

    def decide(sql: str, dialect: str | None) -> None:
        parsed = parse_sql(sql, dialect=dialect, collect_signature_facts=collect)
        engine.evaluate(parsed, agent_id=_AGENT_ID)

    # Warm up (import caches, JIT-free but fills any lazy state).
    for entry in entries:
        decide(entry.sql, entry.dialect)

    samples_ms: list[float] = []
    for _ in range(iterations):
        for entry in entries:
            start = time.perf_counter_ns()
            decide(entry.sql, entry.dialect)
            samples_ms.append((time.perf_counter_ns() - start) / 1e6)
    return percentiles("in_process_decision", samples_ms)


async def deployed_latency(
    base_url: str,
    entries: Sequence[CorpusEntry],
    *,
    qps: int,
    seconds: int,
) -> LatencyStats:
    """Drive sustained load at ~qps for `seconds` and report HTTP round-trip times.

    This includes network/ASGI overhead and is the deployed-latency number, NOT
    the <2ms decision-compute claim.
    """
    interval = 1.0 / qps
    deadline = seconds
    samples_ms: list[float] = []

    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        # Warm up.
        await client.post("/intercept", json={"sql": entries[0].sql, "dialect": entries[0].dialect})

        async def one(sql: str, dialect: str | None) -> None:
            start = time.perf_counter_ns()
            await client.post("/intercept", json={"sql": sql, "dialect": dialect})
            samples_ms.append((time.perf_counter_ns() - start) / 1e6)

        loop = asyncio.get_running_loop()
        end_at = loop.time() + deadline
        tasks: list[asyncio.Task[None]] = []
        i = 0
        while loop.time() < end_at:
            entry = entries[i % len(entries)]
            tasks.append(asyncio.create_task(one(entry.sql, entry.dialect)))
            i += 1
            await asyncio.sleep(interval)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    return percentiles(f"deployed_http_{qps}qps", samples_ms)
