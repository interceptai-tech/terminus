"""Per-agent trust model: enforce is the fail-safe answer everywhere."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from terminus.auth.registry import AgentEntry, AgentRegistry


def _registry() -> AgentRegistry:
    return AgentRegistry(
        agents=[
            AgentEntry(id="observer", trust_level="observe"),
            AgentEntry(id="enforcer", trust_level="enforce"),
            AgentEntry(id="legacy"),  # no trust field
            AgentEntry(id="benched", status="disabled", trust_level="observe"),
        ]
    )


def test_trust_of_matrix() -> None:
    reg = _registry()
    assert reg.trust_of("observer") == "observe"
    assert reg.trust_of("enforcer") == "enforce"
    assert reg.trust_of("legacy") == "enforce"  # absent field -> enforce
    assert reg.trust_of("benched") == "enforce"  # disabled -> enforce
    assert reg.trust_of("ghost") == "enforce"  # unknown -> enforce


def test_malformed_trust_value_rejected_at_load() -> None:
    with pytest.raises(ValidationError):
        AgentEntry(id="bad", trust_level="yolo")  # type: ignore[arg-type]


def test_graduated_autonomy_flag_defaults_off(monkeypatch) -> None:
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    assert settings_mod.get_settings().graduated_autonomy_enabled is False
    settings_mod._settings = None
