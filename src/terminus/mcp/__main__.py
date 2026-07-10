"""Entrypoint: python -m terminus.mcp runs the Terminus MCP enforcement point.

Logs to stderr so stdout remains a clean MCP protocol transport.
"""

from __future__ import annotations

import sys

from terminus.audit.audit_logger import configure_logging
from terminus.config.settings import assert_known_dialect, assert_production_secrets, get_settings
from terminus.mcp.server import build_server


def main() -> None:
    configure_logging(stream=sys.stderr)
    settings = get_settings()
    # TERMINUS_MCP_ENABLED is the documented master switch (docs/configuration.md
    # section 10). Fail fast and loud here, before any server build or connection
    # pool creation, rather than silently doing nothing or building a server that
    # was never meant to run.
    if not settings.mcp_enabled:
        raise RuntimeError(
            "TERMINUS_MCP_ENABLED is false; refusing to start the MCP enforcement "
            "point. Set TERMINUS_MCP_ENABLED=true to activate it."
        )
    assert_production_secrets(settings)
    assert_known_dialect(settings)
    build_server().run()


if __name__ == "__main__":
    main()
