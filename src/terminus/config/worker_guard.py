"""Boot-time guard against silent multi-worker state fragmentation (GAPS H1).

The audit HMAC chain, velocity trackers, and signature store are per-process
globals. Running uvicorn/gunicorn with more than one worker silently splits the
audit chain into N interleaved genesis-rooted segments (the verifier reads them
as broken_link/anchor_mismatch) and multiplies effective velocity thresholds.
This is always true for the audit chain, so the guard is NOT gated behind any
feature flag.

Detection is POSITIVE-EVIDENCE ONLY: an unknown worker count boots. Refusing on
uncertainty would be an availability self-DoS on platforms we cannot introspect
(non-Linux, exotic process managers); operators there attest with
TERMINUS_WORKER_COUNT. Multiple containers/pods with one worker each (the
supported horizontal-scale story) are invisible to every signal below, by
design: no cross-container state is inspected.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

import structlog

from terminus.config.settings import TerminusSettings

_log = structlog.get_logger("terminus.startup")

# uvicorn and gunicorn spell it --workers N, --workers=N, -w N, or -w4.
_WORKERS_FLAG = re.compile(r"(?:^|\s)(?:--workers[=\s]+|-w\s*)(\d+)(?:\s|$)")

_FRAGMENTED_CONTROLS = "audit HMAC chain, velocity trackers, signature store"


def parse_worker_count_from_cmdline(cmdline: str) -> int | None:
    """Extract a worker count from a uvicorn/gunicorn command line.

    Pure function so the parsing is testable without a process tree. Returns
    None when no valid flag is present (including a nonsensical count of 0).
    """
    match = _WORKERS_FLAG.search(cmdline)
    if match is None:
        return None
    count = int(match.group(1))
    return count if count >= 1 else None


def _read_parent_cmdline() -> str | None:
    """Best-effort read of the parent process command line (Linux /proc only).

    Why the PARENT: `uvicorn --workers 4` spawns children via multiprocessing,
    so a worker sees neither the flag in its own argv nor any env marker; the
    supervisor's argv still carries it. Any failure (non-Linux, permissions,
    parent gone) means "unknown", never an error.
    """
    try:
        raw = Path(f"/proc/{os.getppid()}/cmdline").read_bytes()
    except OSError:
        return None
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")


def detect_worker_count(
    settings: TerminusSettings,
    *,
    read_parent_cmdline: Callable[[], str | None] = _read_parent_cmdline,
) -> tuple[int | None, str]:
    """Return (worker_count, source). None means no positive evidence found.

    Precedence: operator attestation (TERMINUS_WORKER_COUNT) beats the
    WEB_CONCURRENCY convention beats parent-cmdline inspection.
    """
    if settings.worker_count is not None:
        return settings.worker_count, "TERMINUS_WORKER_COUNT"

    raw = os.environ.get("WEB_CONCURRENCY", "").strip()
    if raw:
        try:
            value = int(raw)
        except ValueError:
            value = 0
        if value >= 1:
            return value, "WEB_CONCURRENCY"

    cmdline = read_parent_cmdline()
    if cmdline is not None:
        parsed = parse_worker_count_from_cmdline(cmdline)
        if parsed is not None:
            return parsed, "parent_cmdline"

    return None, "unknown"


def assert_single_worker(
    settings: TerminusSettings,
    *,
    read_parent_cmdline: Callable[[], str | None] = _read_parent_cmdline,
) -> None:
    """Refuse to boot a hardened environment with more than one worker.

    development: warn and continue (the test suite and local runs are untouched).
    staging/production: RuntimeError, same fail-fast pattern as
    assert_production_secrets. TERMINUS_ALLOW_UNSAFE_MULTI_WORKER=true boots
    anywhere with a loud warning naming the controls that will fragment.
    """
    count, source = detect_worker_count(settings, read_parent_cmdline=read_parent_cmdline)

    if count is None:
        if settings.environment != "development":
            _log.info(
                "worker_count_unknown",
                detail="no worker-count signal found; assuming one worker. Set "
                "TERMINUS_WORKER_COUNT=1 to attest, or =N to declare.",
            )
        return
    if count <= 1:
        return

    if settings.allow_unsafe_multi_worker:
        _log.warning(
            "multi_worker_override_unsafe",
            workers=count,
            source=source,
            fragmented_controls=_FRAGMENTED_CONTROLS,
            detail="TERMINUS_ALLOW_UNSAFE_MULTI_WORKER is set; audit and velocity "
            "guarantees are void under multiple workers",
        )
        return
    if settings.environment == "development":
        _log.warning(
            "multi_worker_detected",
            workers=count,
            source=source,
            fragmented_controls=_FRAGMENTED_CONTROLS,
        )
        return

    raise RuntimeError(
        f"refusing to start in environment={settings.environment!r} with "
        f"{count} workers (detected via {source}): the {_FRAGMENTED_CONTROLS} "
        "are per-process and silently fragment under multiple workers, which "
        "breaks audit-chain verification. Run ONE worker per container/pod and "
        "scale horizontally, or set TERMINUS_ALLOW_UNSAFE_MULTI_WORKER=true to "
        "boot anyway (unsafe)."
    )
