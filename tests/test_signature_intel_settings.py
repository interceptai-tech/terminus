"""Settings for signature matching + distribution (Phase 2A)."""

import terminus.config.settings as settings_mod
from terminus.config.settings import TerminusSettings


def _fresh() -> TerminusSettings:
    settings_mod._settings = None
    return TerminusSettings()


def test_matching_defaults_off() -> None:
    s = _fresh()
    assert s.signature_matching_enabled is False
    assert s.signature_enforce_enabled is False
    assert s.signature_bundle_source == ""
    assert s.signature_bundle_public_key == ""
    assert s.signature_poll_interval == 0
    assert s.signature_overrides_path == ""


def test_matching_env_override(monkeypatch) -> None:
    monkeypatch.setenv("TERMINUS_SIGNATURE_MATCHING_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_SIGNATURE_ENFORCE_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_SIGNATURE_POLL_INTERVAL", "300")
    s = _fresh()
    assert s.signature_matching_enabled is True
    assert s.signature_enforce_enabled is True
    assert s.signature_poll_interval == 300
    settings_mod._settings = None
