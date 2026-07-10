"""The executor: the only code that runs SQL and the only holder of DB credentials.

Its run() accepts ONLY an ExecutionGrant, so there is no callable path from a deny or
an unresolved approval to execution. Credentials never appear in a result or error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from terminus.mcp.grants import ExecutionGrant


@runtime_checkable
class ConnectionPool(Protocol):
    """The minimal async Postgres surface the executor needs (asyncpg-compatible)."""

    async def fetch(self, sql: str) -> list[dict[str, Any]]: ...

    async def execute(self, sql: str) -> str: ...


@dataclass
class ExecResult:
    """Result of running one allowed statement."""

    rows: list[dict[str, Any]]
    row_count: int


_ROWCOUNT_RE = re.compile(r"(\d+)\s*$")


class Executor:
    """Runs an allowed grant against Postgres. Sole creds holder."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    async def run(self, grant: ExecutionGrant, *, read: bool) -> ExecResult:
        if not isinstance(grant, ExecutionGrant):
            raise TypeError("Executor.run requires an ExecutionGrant, never raw SQL")
        if read:
            rows = await self._pool.fetch(grant.statement)
            return ExecResult(rows=list(rows), row_count=len(rows))
        status = await self._pool.execute(grant.statement)
        match = _ROWCOUNT_RE.search(status or "")
        return ExecResult(rows=[], row_count=int(match.group(1)) if match else 0)
