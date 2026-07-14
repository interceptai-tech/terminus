from __future__ import annotations

import pytest
from pydantic import ValidationError

from terminus.config.settings import TerminusSettings


def test_reveal_threshold_default_and_bounds() -> None:
    s = TerminusSettings()
    assert s.mcp_approval_reveal_threshold == 0.9
    assert s.mcp_approval_max_holds == 32
    with pytest.raises(ValidationError):
        TerminusSettings(mcp_approval_reveal_threshold=1.5)
    with pytest.raises(ValidationError):
        TerminusSettings(mcp_approval_max_holds=0)


def test_reveal_threshold_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_REVEAL_THRESHOLD", "0.95")
    monkeypatch.setenv("TERMINUS_MCP_APPROVAL_MAX_HOLDS", "8")
    s = TerminusSettings()
    assert s.mcp_approval_reveal_threshold == 0.95
    assert s.mcp_approval_max_holds == 8
