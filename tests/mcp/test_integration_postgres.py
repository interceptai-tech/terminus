"""Integration tests against a live Postgres database.

Skipped unless TERMINUS_TEST_POSTGRES_DSN environment variable is set.
Requires a throwaway Postgres instance.
"""

from __future__ import annotations

import os

import pytest

DSN = os.environ.get("TERMINUS_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="TERMINUS_TEST_POSTGRES_DSN not set")


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    """Set development environment and reset cached settings for this test.

    Ensures that each test starts with a fresh settings cache so that
    TERMINUS_ENVIRONMENT=development takes effect.
    """
    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "development")
    import terminus.config.settings as settings_mod

    settings_mod._settings = None
    yield
    settings_mod._settings = None


async def _service(agent_id="analytics_agent_42"):
    """Create a ToolService connected to a live Postgres database.

    Sets up the database schema and an initial row, then returns a fully
    configured ToolService ready for queries and executes.
    """
    import asyncpg

    from terminus.audit.audit_logger import AuditLogger, configure_logging
    from terminus.config.settings import get_settings
    from terminus.mcp.approvals import ApprovalBroker
    from terminus.mcp.executor import Executor
    from terminus.mcp.server import ToolService, _AsyncpgPool
    from terminus.policy.policy_engine import get_policy_engine

    configure_logging()
    pool = await asyncpg.create_pool(dsn=DSN)
    await pool.execute(
        "CREATE SCHEMA IF NOT EXISTS public;"
        "CREATE TABLE IF NOT EXISTS public.users (id int primary key, name text, email text);"
        "INSERT INTO public.users (id, name, email) VALUES (1, 'a', 'a@x.io') "
        "ON CONFLICT DO NOTHING;"
    )
    return ToolService(
        settings=get_settings(),
        policy_engine=get_policy_engine(),
        executor=Executor(_AsyncpgPool(pool)),
        broker=ApprovalBroker(),
        audit_logger=AuditLogger(),
        agent_id=agent_id,
    )


async def test_allowed_read_returns_rows():
    """Allowed read query returns rows."""
    svc = await _service()
    result = await svc.query("SELECT id, name FROM public.users WHERE id = 1")
    assert result["status"] == "ok"
    assert result["rows"][0]["id"] == 1


async def test_blocked_write_does_not_mutate():
    """Blocked write query is denied and does not mutate the database."""
    svc = await _service()
    before = await svc.query("SELECT id FROM public.users WHERE id = 1")
    result = await svc.execute("DELETE FROM public.users WHERE id = 1")
    assert result["status"] == "denied"
    after = await svc.query("SELECT id FROM public.users WHERE id = 1")
    assert after["rows"] == before["rows"]
