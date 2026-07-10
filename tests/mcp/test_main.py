from __future__ import annotations

import pytest

from terminus.mcp import __main__ as main_mod


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    yield
    settings_mod._settings = None


def test_main_raises_when_mcp_disabled(monkeypatch):
    # TERMINUS_MCP_ENABLED unset -> defaults to False (the documented master switch).
    monkeypatch.delenv("TERMINUS_MCP_ENABLED", raising=False)
    import terminus.config.settings as settings_mod

    settings_mod._settings = None

    def _must_not_be_called() -> None:
        raise AssertionError("build_server() must not run when TERMINUS_MCP_ENABLED is false")

    monkeypatch.setattr(main_mod, "build_server", _must_not_be_called)

    with pytest.raises(RuntimeError, match="TERMINUS_MCP_ENABLED"):
        main_mod.main()


def test_main_raises_when_mcp_explicitly_false(monkeypatch):
    monkeypatch.setenv("TERMINUS_MCP_ENABLED", "false")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None

    def _must_not_be_called() -> None:
        raise AssertionError("build_server() must not run when TERMINUS_MCP_ENABLED is false")

    monkeypatch.setattr(main_mod, "build_server", _must_not_be_called)

    with pytest.raises(RuntimeError, match="TERMINUS_MCP_ENABLED"):
        main_mod.main()
