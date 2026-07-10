"""Environment-keyed settings defaults (P1 hardening, spec section 2).

None means "auto": _apply_environment_defaults fills the value keyed on
`environment`. Direct TerminusSettings(...) kwargs beat env vars, so most tests
construct settings directly; the env-var override tests use monkeypatch.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from terminus.config.settings import TerminusSettings


def test_development_auto_defaults_match_today() -> None:
    s = TerminusSettings(environment="development")
    assert s.jwt_require_exp is False
    assert s.disable_docs is False
    assert s.audit_checkpoint_interval == 0


@pytest.mark.parametrize("env", ["staging", "production"])
def test_hardened_auto_defaults(env: str) -> None:
    s = TerminusSettings(environment=env)  # type: ignore[arg-type]
    assert s.jwt_require_exp is True
    assert s.disable_docs is True
    assert s.audit_checkpoint_interval == 1000


def test_explicit_env_var_beats_auto_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_JWT_REQUIRE_EXP", "false")
    monkeypatch.setenv("TERMINUS_DISABLE_DOCS", "false")
    monkeypatch.setenv("TERMINUS_AUDIT_CHECKPOINT_INTERVAL", "0")
    s = TerminusSettings(environment="production")
    assert s.jwt_require_exp is False
    assert s.disable_docs is False
    assert s.audit_checkpoint_interval == 0


def test_explicit_env_var_beats_auto_in_development(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_JWT_REQUIRE_EXP", "true")
    monkeypatch.setenv("TERMINUS_DISABLE_DOCS", "true")
    monkeypatch.setenv("TERMINUS_AUDIT_CHECKPOINT_INTERVAL", "500")
    s = TerminusSettings(environment="development")
    assert s.jwt_require_exp is True
    assert s.disable_docs is True
    assert s.audit_checkpoint_interval == 500


def test_new_plain_fields_default_off() -> None:
    s = TerminusSettings(environment="production")
    assert s.jwt_max_lifetime_seconds == 0
    assert s.worker_count is None
    assert s.allow_unsafe_multi_worker is False


def test_worker_count_rejects_zero() -> None:
    with pytest.raises(ValidationError):
        TerminusSettings(environment="development", worker_count=0)
