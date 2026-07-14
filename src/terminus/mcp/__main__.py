"""Entrypoint: python -m terminus.mcp runs the Terminus MCP enforcement point.

Logs to stderr so stdout remains a clean MCP protocol transport.
"""

from __future__ import annotations

import sys

import structlog

from terminus.audit.audit_logger import configure_logging
from terminus.config.settings import (
    assert_known_dialect,
    assert_plane_config,
    assert_production_secrets,
    get_settings,
)
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
    assert_plane_config(settings)
    if settings.plane_enabled:
        from terminus.plane.enrollment import load_plane_context

        log = structlog.get_logger("terminus.mcp")
        ctx = load_plane_context(settings)
        log.info(
            "plane_context_loaded",
            deployment_id=ctx.identity.deployment_id,
            deployment_fp=ctx.identity.fingerprint(),
            trust_root_fp=ctx.trust_root_fingerprint,
            operators=ctx.operator_count,
        )
    build_server().run()


if __name__ == "__main__":
    main()
