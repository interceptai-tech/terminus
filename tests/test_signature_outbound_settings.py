"""Phase 2B outbound telemetry settings."""

import terminus.config.settings as settings_mod
from terminus.config.settings import TerminusSettings


def _fresh() -> TerminusSettings:
    settings_mod._settings = None
    return TerminusSettings()


def test_outbound_defaults() -> None:
    s = _fresh()
    assert s.signature_outbound_enabled is False
    assert s.signature_hub_ingest_url == ""
    assert s.signature_hub_token == ""
    assert s.signature_outbound_flush_interval == 30
    assert s.signature_outbound_batch_max == 100
    assert s.signature_outbound_buffer_max == 1000


def test_outbound_env_override(monkeypatch) -> None:
    monkeypatch.setenv("TERMINUS_SIGNATURE_OUTBOUND_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_SIGNATURE_HUB_INGEST_URL", "https://hub.example/ingest")
    monkeypatch.setenv("TERMINUS_SIGNATURE_OUTBOUND_BATCH_MAX", "50")
    s = _fresh()
    assert s.signature_outbound_enabled is True
    assert s.signature_hub_ingest_url == "https://hub.example/ingest"
    assert s.signature_outbound_batch_max == 50
    settings_mod._settings = None
