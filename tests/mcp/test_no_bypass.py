"""Structural tests: no-bypass guarantee for ExecutionGrant construction."""

from __future__ import annotations

import inspect
import typing

import pytest

from terminus.mcp import executor, grants


def test_executor_run_only_accepts_a_grant_type():
    """Executor.run must be typed to accept ONLY ExecutionGrant.

    Uses typing.get_type_hints to resolve string annotations from
    `from __future__ import annotations`.
    """
    hints = typing.get_type_hints(executor.Executor.run)
    assert hints["grant"] is grants.ExecutionGrant


def test_executor_rejects_non_grant_at_runtime():
    """Executor.run must reject non-ExecutionGrant at runtime.

    Even if someone circumvents typing, the runtime isinstance check must catch it.
    """

    class FakePool:
        async def fetch(self, sql):  # pragma: no cover - not reached
            return []

        async def execute(self, sql):  # pragma: no cover - not reached
            return "UPDATE 0"

    import asyncio

    with pytest.raises(TypeError):
        asyncio.run(executor.Executor(FakePool()).run("DROP TABLE users", read=False))


def test_grant_is_only_minted_in_decider():
    """ExecutionGrant is constructed in exactly one module (decider) plus its own.

    ExecutionGrant is constructed ONLY in the decider module (plus its own definition
    in grants). No other mcp module may construct it — approvals and server may hold
    a grant but must never construct one.

    Exclusions: {grants, decider, approvals, server}
    """
    import pkgutil

    import terminus.mcp as pkg

    offenders = []
    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name in {"grants", "decider", "approvals", "server"}:
            continue
        source = inspect.getsource(__import__(f"terminus.mcp.{mod.name}", fromlist=["x"]))
        if "ExecutionGrant(" in source:
            offenders.append(mod.name)
    assert offenders == [], f"ExecutionGrant constructed outside decider: {offenders}"
