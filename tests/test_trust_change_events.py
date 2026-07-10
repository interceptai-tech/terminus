"""The trust-change event is prev-chained: deleting or tampering it breaks the chain."""

from __future__ import annotations

import json

import pytest

from terminus.audit.audit_logger import (
    TRUST_CHANGE_SIGNED_FIELDS,
    AuditLogger,
    configure_logging,
)
from terminus.audit.verify import verify_audit_chain
from terminus.config.settings import get_settings
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    configure_logging()
    yield
    settings_mod._settings = None


def _emit_session(capsys) -> list[str]:
    """One decision, one trust change, one decision: a realistic promotion window."""
    logger = AuditLogger()
    parsed = parse_sql("DROP TABLE public.users")
    decision = PolicyEngine.from_default_policy().evaluate(parsed, agent_id="a1")

    def emit_decision(rid: str) -> None:
        logger.log_decision(
            request_id=rid,
            sql="DROP TABLE public.users",
            agent_id="a1",
            parsed_sql=parsed,
            decision=decision,
            remediation_present=True,
        )

    emit_decision("r1")
    logger.log_trust_change(
        agent_id="onboarding_agent_9",
        previous_trust_level="observe",
        new_trust_level="enforce",
        governance_version="abc123def456",
        trust_changed_by="will",
        trust_change_reason="clean 30-day observe record",
    )
    emit_decision("r2")
    return [ln for ln in capsys.readouterr().out.strip().splitlines() if ln]


def test_interleaved_chain_verifies(capsys):
    lines = _emit_session(capsys)
    key = get_settings().audit_hmac_key
    result = verify_audit_chain(lines, key)
    assert result.ok, result.failures
    assert result.verified_count == 3


def test_deleting_the_trust_event_breaks_linkage(capsys):
    lines = _emit_session(capsys)
    key = get_settings().audit_hmac_key
    pruned = [ln for ln in lines if "terminus_trust_level_change" not in ln]
    assert len(pruned) == len(lines) - 1
    result = verify_audit_chain(pruned, key)
    assert not result.ok
    assert any(f.reason in {"broken_link", "sequence_gap"} for f in result.failures)


def test_tampered_trust_target_detected(capsys):
    lines = _emit_session(capsys)
    key = get_settings().audit_hmac_key
    doctored = []
    for ln in lines:
        if "terminus_trust_level_change" in ln:
            ev = json.loads(ln)
            ev["new_trust_level"] = "observe"  # forge a demotion into a promotion
            ln = json.dumps(ev)
        doctored.append(ln)
    result = verify_audit_chain(doctored, key)
    assert not result.ok
    assert any(f.reason == "signature_mismatch" for f in result.failures)


def test_trust_event_carries_provenance(capsys):
    lines = _emit_session(capsys)
    ev = json.loads(next(ln for ln in lines if "terminus_trust_level_change" in ln))
    assert ev["trust_changed_by"] == "will"
    assert ev["previous_trust_level"] == "observe"
    assert ev["new_trust_level"] == "enforce"
    assert set(TRUST_CHANGE_SIGNED_FIELDS) <= set(ev.keys())
