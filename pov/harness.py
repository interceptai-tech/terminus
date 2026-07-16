"""PoV validation harness CLI.

Runs the functional + self-correction pass and the audit-completeness pass
in-process (FastAPI TestClient, with the audit stream captured), times the
in-process decision path, optionally drives a deployed-latency load sweep against
a running Terminus, assembles a RunResult, writes the artifacts, and exits
non-zero if any hard criterion fails.
"""

from __future__ import annotations

import argparse
import asyncio
import io
from collections.abc import Sequence
from pathlib import Path

import structlog
from fastapi.testclient import TestClient

from pov.audit_check import check_audit_completeness
from pov.functional import run_functional, self_correction_breakdown
from pov.latency import deployed_latency, in_process_latency
from pov.loader import load_corpus
from pov.models import CorpusEntry
from pov.report import RunResult, write_report
from terminus.audit import audit_logger as al
from terminus.config.settings import get_settings
from terminus.main import app

_CORPUS = Path(__file__).resolve().parent / "corpus.yaml"


def _capture_structlog_to_buffer() -> io.StringIO:
    """Point structlog at a buffer with the production processor chain so we can
    capture the rendered audit stream the functional pass produces."""
    buf = io.StringIO()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=buf),
        cache_logger_on_first_use=False,
    )
    return buf


def run_in_process(
    *,
    out_dir: str | Path,
    entries: Sequence[CorpusEntry] | None = None,
    corpus_path: str | Path | None = None,
) -> RunResult:
    """Run the functional, audit, and in-process latency passes (no server)."""
    if entries is not None:
        corpus = list(entries)
    else:
        corpus = load_corpus(corpus_path if corpus_path is not None else _CORPUS)
    settings = get_settings()

    # Reset the segment counter alongside the head so the run's chain starts at
    # sequence 0 (a genesis-rooted segment the audit pass verifies from sequence 0).
    al._last_signature = al.GENESIS_SIGNATURE
    al._sequence = 0
    try:
        with TestClient(app) as client:
            # Reconfigure structlog to capture into a buffer AFTER the app lifespan
            # has started (lifespan calls configure_logging(), which would overwrite
            # any buffer we set up before entering the TestClient context).
            buf = _capture_structlog_to_buffer()
            outcomes = run_functional(client, corpus)
    finally:
        al.configure_logging()

    audit_lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    audit = check_audit_completeness(audit_lines, [e.id for e in corpus], settings.audit_hmac_key)

    result = RunResult(
        outcomes=outcomes,
        self_correction=self_correction_breakdown(outcomes),
        audit=audit,
        in_process_latency=in_process_latency(corpus),
        deployed_latency=[],
    )
    write_report(result, out_dir)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pov.harness", description="Terminus PoV validation harness"
    )
    parser.add_argument("--out", default="pov/out", help="output directory for artifacts")
    parser.add_argument(
        "--corpus", default=None, help="path to the corpus YAML (default: pov/corpus.yaml)"
    )
    parser.add_argument(
        "--url", default=None, help="running Terminus base URL for the deployed-latency sweep"
    )
    parser.add_argument(
        "--qps", default="50,100,200", help="comma-separated QPS targets for the load sweep"
    )
    parser.add_argument("--seconds", type=int, default=20, help="seconds per QPS step")
    args = parser.parse_args(argv)

    result = run_in_process(out_dir=args.out, corpus_path=args.corpus)

    if args.url:
        corpus = load_corpus(args.corpus if args.corpus is not None else _CORPUS)
        for qps in (int(q) for q in args.qps.split(",")):
            result.deployed_latency.append(
                asyncio.run(deployed_latency(args.url, corpus, qps=qps, seconds=args.seconds))
            )
        write_report(result, args.out)  # re-emit with the deployed numbers

    failures = result.gate()
    if failures:
        print("PoV FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"PoV PASSED. Decision p99 {result.in_process_latency.p99_ms:.3f}ms; "
        f"artifacts in {args.out}/"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
