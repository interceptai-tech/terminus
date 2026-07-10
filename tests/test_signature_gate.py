"""The cheap emit gate."""

from typing import Any

from terminus.config.settings import TerminusSettings
from terminus.parser.sql_parser import ParsedSQL, SecurityFlags
from terminus.policy.policy_engine import PolicyDecision
from terminus.signature.gate import should_emit_signature


def _settings(**over: Any) -> TerminusSettings:
    return TerminusSettings(**over)


def _parsed(risk: float = 0.1, **flags: Any) -> ParsedSQL:
    return ParsedSQL(operation="SELECT", risk_score=risk, security_flags=SecurityFlags(**flags))


def _allow() -> PolicyDecision:
    return PolicyDecision(action="allow", reason="ok", reason_code="policy_rule")


def _deny() -> PolicyDecision:
    return PolicyDecision(action="deny", reason="no", reason_code="default")


def test_disabled_never_emits() -> None:
    assert should_emit_signature(_deny(), _parsed(), _settings(signatures_enabled=False)) is False


def test_deny_always_emits() -> None:
    assert should_emit_signature(_deny(), _parsed(), _settings()) is True


def test_smuggling_allow_emits() -> None:
    assert should_emit_signature(_allow(), _parsed(has_smuggling_pattern=True), _settings()) is True


def test_hidden_subquery_allow_emits() -> None:
    assert should_emit_signature(_allow(), _parsed(has_hidden_subquery=True), _settings()) is True


def test_high_risk_allow_emits() -> None:
    assert should_emit_signature(_allow(), _parsed(risk=0.5), _settings()) is True


def test_low_risk_allow_skipped() -> None:
    assert should_emit_signature(_allow(), _parsed(risk=0.1), _settings()) is False
