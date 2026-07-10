"""Audit completeness check: one event per request + a verified chain."""

from __future__ import annotations

import io

import structlog

from pov.audit_check import check_audit_completeness
from terminus.audit import audit_logger as al
from terminus.config.settings import get_settings
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine


def _emit(sqls: list[str]) -> list[str]:
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
    try:
        al._last_signature = al.GENESIS_SIGNATURE
        al._sequence = 0
        logger = al.AuditLogger()
        engine = PolicyEngine.from_default_policy()
        for i, sql in enumerate(sqls):
            parsed = parse_sql(sql)
            decision = engine.evaluate(parsed, agent_id="analytics_agent_42")
            logger.log_decision(
                request_id=f"r{i}",
                sql=sql,
                agent_id="analytics_agent_42",
                parsed_sql=parsed,
                decision=decision,
                remediation_present=False,
            )
        return [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    finally:
        al.configure_logging()


def test_complete_chain_passes() -> None:
    sqls = ["SELECT id FROM public.users WHERE id = 1", "DROP TABLE public.users"]
    lines = _emit(sqls)
    result = check_audit_completeness(lines, ["r0", "r1"], get_settings().audit_hmac_key)
    assert result.complete
    assert result.audited == 2
    assert result.chain_ok


def test_missing_event_is_incomplete() -> None:
    lines = _emit(["SELECT id FROM public.users WHERE id = 1"])
    result = check_audit_completeness(lines, ["r0", "r1"], get_settings().audit_hmac_key)
    assert not result.complete  # only 1 of 2 request_ids audited
