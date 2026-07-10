"""Tests for TerminusSettings secret-length validation (fail-fast at startup)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from terminus.config.settings import TerminusSettings, assert_production_secrets


def test_default_secrets_meet_minimum() -> None:
    # The shipped defaults are well over 32 bytes, so a default deployment is unaffected.
    settings = TerminusSettings()
    assert len(settings.jwt_secret.encode("utf-8")) >= 32
    assert len(settings.audit_hmac_key.encode("utf-8")) >= 32


def test_max_sql_length_defaults_to_16_kib() -> None:
    # Conservative parse cap: bounds worst-case event-loop block, configurable up.
    assert TerminusSettings().max_sql_length == 16_384


def test_enforce_injection_block_defaults_on() -> None:
    # Allow-path injection enforcement ships default-on (closes the F3 hole out of the box).
    assert TerminusSettings().enforce_injection_block is True


def test_short_jwt_secret_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", "too-short")
    with pytest.raises(ValidationError, match="jwt_secret"):
        TerminusSettings()


def test_short_audit_hmac_key_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_AUDIT_HMAC_KEY", "too-short")
    with pytest.raises(ValidationError, match="audit_hmac_key"):
        TerminusSettings()


def test_exactly_32_bytes_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_JWT_SECRET", "x" * 32)
    monkeypatch.setenv("TERMINUS_AUDIT_HMAC_KEY", "y" * 32)
    settings = TerminusSettings()
    assert settings.jwt_secret == "x" * 32
    assert settings.audit_hmac_key == "y" * 32


# --- Production boot guard: refuse to start with publicly-known default secrets ---
# Length alone is not evidence of secrecy: the shipped defaults are >= 32 bytes,
# so the length validator passes them and a zero-config deploy would run in
# production with a forgeable audit chain and spoofable agent identity.

_STRONG_JWT = "prod-jwt-secret-not-a-default-value-1234567890"
_STRONG_HMAC = "prod-audit-hmac-key-not-a-default-value-1234567890"


def test_production_boot_rejects_default_jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "production")
    monkeypatch.setenv("TERMINUS_AUDIT_HMAC_KEY", _STRONG_HMAC)  # isolate the JWT default
    with pytest.raises(RuntimeError, match="jwt_secret"):
        assert_production_secrets(TerminusSettings())


def test_production_boot_rejects_default_audit_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "production")
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _STRONG_JWT)  # isolate the audit-key default
    with pytest.raises(RuntimeError, match="audit_hmac_key"):
        assert_production_secrets(TerminusSettings())


def test_staging_also_rejects_default_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "staging")
    with pytest.raises(RuntimeError):
        assert_production_secrets(TerminusSettings())


def test_development_allows_default_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    assert_production_secrets(TerminusSettings())  # must not raise


def test_production_with_strong_secrets_boots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "production")
    monkeypatch.setenv("TERMINUS_JWT_SECRET", _STRONG_JWT)
    monkeypatch.setenv("TERMINUS_AUDIT_HMAC_KEY", _STRONG_HMAC)
    assert_production_secrets(TerminusSettings())  # must not raise
