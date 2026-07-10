"""Settings for the signature extractor."""

import terminus.config.settings as settings_mod
from terminus.config.settings import TerminusSettings


def _fresh() -> TerminusSettings:
    settings_mod._settings = None
    return TerminusSettings()


def test_signature_defaults() -> None:
    s = _fresh()
    assert s.signatures_enabled is True
    assert s.signature_risk_threshold == 0.5


def test_signature_settings_env_override(monkeypatch) -> None:
    monkeypatch.setenv("TERMINUS_SIGNATURES_ENABLED", "false")
    monkeypatch.setenv("TERMINUS_SIGNATURE_RISK_THRESHOLD", "0.8")
    s = _fresh()
    assert s.signatures_enabled is False
    assert s.signature_risk_threshold == 0.8
    settings_mod._settings = None  # avoid leaking into other tests
