"""Prometheus metrics for Terminus observability."""

from __future__ import annotations

import time

from prometheus_client import Counter, Gauge, Histogram, generate_latest
from starlette.responses import Response

# Core metrics
REQUESTS_TOTAL = Counter(
    "terminus_requests_total",
    "Total number of intercepted SQL requests",
    ["action", "reason", "operation"],
)

SMUGGLING_ATTEMPTS_TOTAL = Counter(
    "terminus_smuggling_attempts_total",
    "Number of detected SQL smuggling attempts",
    ["reason"],
)

PARSER_LATENCY = Histogram(
    "terminus_parser_latency_seconds",
    "Time spent in SQL parsing and security analysis (AST walk)",
    buckets=(0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

ACTIVE_AGENTS = Gauge(
    "terminus_active_agents",
    "Number of unique agents seen in the current time window",
)

BUILD_INFO = Gauge("terminus_build_info", "Build information", ["version", "environment"])

AUTH_EVENTS = Counter(
    "terminus_auth_events_total",
    "Agent authentication outcomes",
    ["result"],  # verified | rejected | legacy
)

SIGNATURE_MATCHES = Counter(
    "terminus_signature_matches_total",
    "Signature matches by mode and severity",
    ["mode", "severity"],
)

VELOCITY_ANOMALIES = Counter(
    "terminus_velocity_anomaly_total",
    "Per-agent query-velocity anomalies (possible extraction oracle)",
    ["enforced"],  # "true" | "false" (low-cardinality)
)

SIGNATURE_VERSION_SKEW = Counter(
    "terminus_signature_version_skew_total",
    "Signature records skipped due to a fingerprint_version mismatch",
)

CONFIG_RELOAD_TOTAL = Counter(
    "terminus_config_reload_total",
    "Governance config reload attempts by result",
    ["result"],  # applied | unchanged | failed
)

CONFIG_LAST_RELOAD_TIMESTAMP = Gauge(
    "terminus_config_last_reload_timestamp",
    "Epoch seconds of the last successful governance config reload",
)

RATE_LIMITER_UNAVAILABLE_TOTAL = Counter(
    "terminus_rate_limiter_unavailable_total",
    "Rate limiter unavailable, skipped, or erroring (Redis health)",
)

SIGNATURE_BUNDLE_UPDATE_FAILED_TOTAL = Counter(
    "terminus_signature_bundle_update_failed_total",
    "Failed inbound signed signature-bundle updates (last-known-good retained)",
)

WOULD_DENY_TOTAL = Counter(
    "terminus_would_deny_total",
    "Observe-mode requests that would have been denied under enforce",
    ["reason_code", "operation"],
)


def record_would_deny(reason_code: str, operation: str) -> None:
    """Count an observe-mode softening: this request would have been denied."""
    WOULD_DENY_TOTAL.labels(reason_code=reason_code, operation=operation).inc()


def record_config_reload(result: str) -> None:
    """Count a reload outcome; stamp the timestamp only on a successful apply."""
    CONFIG_RELOAD_TOTAL.labels(result=result).inc()
    if result == "applied":
        CONFIG_LAST_RELOAD_TIMESTAMP.set(time.time())


def record_rate_limiter_unavailable() -> None:
    """Count a rate-limiter unavailability, skip, or error (Redis health signal)."""
    RATE_LIMITER_UNAVAILABLE_TOTAL.inc()


def record_signature_bundle_update_failed() -> None:
    """Count a failed inbound signature-bundle update (last-known-good retained)."""
    SIGNATURE_BUNDLE_UPDATE_FAILED_TOTAL.inc()


_active_agents: set[str] = set()


def track_active_agent(agent_id: str | None) -> None:
    """Track unique agent_id for the active agents gauge."""
    if agent_id and agent_id != "unknown":
        _active_agents.add(agent_id)
        ACTIVE_AGENTS.set(len(_active_agents))


def record_request(
    action: str,
    reason_code: str,
    operation: str = "unknown",
    *,
    smuggling: bool = False,
    agent_id: str | None = None,
) -> None:
    """Record one intercepted request against the Prometheus counters.

    ``reason_code`` MUST be a low-cardinality code (e.g. ``policy_rule``,
    ``schema_whitelist``, ``default``) and never the free-form human reason or a
    table/SQL fragment. Prometheus stores one time series per label combination,
    so a high-cardinality label would blow up memory: think of it like a syslog
    facility code, not the full log line.
    """
    REQUESTS_TOTAL.labels(action=action, reason=reason_code, operation=operation).inc()
    if smuggling:
        SMUGGLING_ATTEMPTS_TOTAL.labels(reason=reason_code).inc()
    if agent_id:
        track_active_agent(agent_id)


def observe_parser_latency(duration_seconds: float) -> None:
    """Record parser + security analysis latency."""
    PARSER_LATENCY.observe(duration_seconds)


def record_auth_event(result: str) -> None:
    """Record an authentication outcome. result is verified | rejected | legacy."""
    AUTH_EVENTS.labels(result=result).inc()


def record_signature_match(mode: str, severity: str) -> None:
    """Record a known-bad signature match (observe or enforce)."""
    SIGNATURE_MATCHES.labels(mode=mode, severity=severity).inc()


def record_velocity_anomaly(enforced: bool) -> None:
    """Count a velocity anomaly. ``enforced`` stays low-cardinality (true|false)."""
    VELOCITY_ANOMALIES.labels(enforced=str(enforced).lower()).inc()


def record_version_skew(count: int) -> None:
    """Record records skipped because their fingerprint_version did not match."""
    if count > 0:
        SIGNATURE_VERSION_SKEW.inc(count)


SIGNATURE_OUTBOUND_SENT = Counter(
    "terminus_signature_outbound_sent_total",
    "Outbound signature payloads successfully POSTed to the Hub",
)
SIGNATURE_OUTBOUND_FAILED = Counter(
    "terminus_signature_outbound_failed_total",
    "Outbound signature payloads dropped after all POST retries failed",
)
SIGNATURE_OUTBOUND_DROPPED = Counter(
    "terminus_signature_outbound_dropped_total",
    "Outbound signature payloads dropped by buffer overflow",
)
SIGNATURE_OUTBOUND_GUARD_TRIPPED = Counter(
    "terminus_signature_outbound_guard_tripped_total",
    "Signatures dropped by the privacy guard before outbound enqueue",
)
SIGNATURE_EMITTER_ERRORS = Counter(
    "terminus_signature_emitter_errors_total",
    "A CompositeEmitter leg raised during emit",
    ["leg"],
)


def record_outbound_sent(count: int) -> None:
    """Record payloads successfully POSTed (after any number of retries)."""
    if count > 0:
        SIGNATURE_OUTBOUND_SENT.inc(count)


def record_outbound_failed(count: int) -> None:
    """Record payloads dropped after all POST retries failed."""
    if count > 0:
        SIGNATURE_OUTBOUND_FAILED.inc(count)


def record_outbound_dropped() -> None:
    """Record one payload dropped by buffer overflow."""
    SIGNATURE_OUTBOUND_DROPPED.inc()


def record_outbound_guard_tripped() -> None:
    """Record one signature dropped by the privacy guard before enqueue."""
    SIGNATURE_OUTBOUND_GUARD_TRIPPED.inc()


def record_emitter_error(leg: str) -> None:
    """Record one CompositeEmitter leg raising during emit."""
    SIGNATURE_EMITTER_ERRORS.labels(leg=leg).inc()


class MetricsHandler:
    """FastAPI-compatible metrics endpoint."""

    @staticmethod
    async def get_metrics() -> Response:
        """Expose Prometheus metrics."""
        return Response(
            generate_latest(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )


# Expose for router
metrics_router = MetricsHandler()
