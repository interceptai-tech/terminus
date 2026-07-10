from __future__ import annotations

from typing import Any

import pytest

from terminus.mcp.executor import Executor
from terminus.mcp.grants import ExecutionGrant


class FakePool:
    def __init__(self):
        self.fetched: list[str] = []
        self.executed: list[str] = []

    async def fetch(self, sql: str) -> list[dict[str, Any]]:
        self.fetched.append(sql)
        return [{"id": 1}]

    async def execute(self, sql: str) -> str:
        self.executed.append(sql)
        return "UPDATE 1"


async def test_run_read_uses_fetch():
    pool = FakePool()
    grant = ExecutionGrant(statement="SELECT id FROM t", agent_id="a", request_id="r")
    result = await Executor(pool).run(grant, read=True)
    assert result.rows == [{"id": 1}]
    assert pool.fetched == ["SELECT id FROM t"]
    assert pool.executed == []


async def test_run_write_uses_execute_and_parses_row_count():
    pool = FakePool()
    grant = ExecutionGrant(statement="UPDATE t SET x=1 WHERE id=1", agent_id="a", request_id="r")
    result = await Executor(pool).run(grant, read=False)
    assert result.row_count == 1
    assert pool.executed == ["UPDATE t SET x=1 WHERE id=1"]


async def test_executor_run_rejects_non_grant():
    pool = FakePool()
    with pytest.raises(TypeError):
        await Executor(pool).run("SELECT 1", read=True)  # type: ignore[arg-type]
