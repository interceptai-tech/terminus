from __future__ import annotations

import terminus.config.settings as settings_mod


def test_mcp_settings_defaults(monkeypatch):
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    settings_mod._settings = None
    s = settings_mod.get_settings()
    assert s.mcp_enabled is False
    assert s.mcp_agent_id == ""
    assert s.mcp_postgres_dsn == ""
    assert s.mcp_approval_risk_threshold == 0.8
    assert s.mcp_approval_timeout_seconds == 300
    settings_mod._settings = None
