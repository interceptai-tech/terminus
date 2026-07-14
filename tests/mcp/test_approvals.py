from __future__ import annotations

import asyncio

from terminus.mcp.approvals import ApprovalBroker, ApprovalResult
from terminus.mcp.grants import ExecutionGrant


def _grant():
    return ExecutionGrant(statement="UPDATE t SET x=1", agent_id="a", request_id="r1")


async def test_approve_releases_grant():
    broker = ApprovalBroker()
    rid = broker.submit(_grant(), reason="high risk")
    assert rid in broker.pending()

    async def approver():
        await asyncio.sleep(0.01)
        assert broker.approve(rid) is True

    task = asyncio.create_task(approver())
    result, grant, _provenance = await broker.wait(rid, timeout=1.0)
    await task
    assert result is ApprovalResult.APPROVED
    assert grant is not None and grant.statement == "UPDATE t SET x=1"
    assert rid not in broker.pending()


async def test_deny_returns_no_grant():
    broker = ApprovalBroker()
    rid = broker.submit(_grant(), reason="high risk")

    async def denier():
        await asyncio.sleep(0.01)
        broker.deny(rid)

    task = asyncio.create_task(denier())
    result, grant, _provenance = await broker.wait(rid, timeout=1.0)
    await task
    assert result is ApprovalResult.DENIED
    assert grant is None


async def test_first_decision_wins_deny_is_sticky():
    # Race window: deny resolves the entry, but before the single waiter
    # resumes (event.set only marks it runnable), a later approve must NOT
    # flip the result to APPROVED and leak the grant. First decision wins.
    broker = ApprovalBroker()
    rid = broker.submit(_grant(), reason="high risk")
    assert broker.deny(rid) is True
    assert broker.approve(rid) is False
    result, grant, _provenance = await broker.wait(rid, timeout=1.0)
    assert result is ApprovalResult.DENIED
    assert grant is None


async def test_timeout_expires_as_no_grant():
    broker = ApprovalBroker()
    rid = broker.submit(_grant(), reason="high risk")
    result, grant, provenance = await broker.wait(rid, timeout=0.05)
    assert result is ApprovalResult.EXPIRED
    assert grant is None
    assert provenance is None
    assert rid not in broker.pending()


async def test_wait_returns_operator_provenance() -> None:
    broker = ApprovalBroker()
    rid = broker.submit(_grant(), reason="high risk")
    assert broker.approve(rid, operator_id="alice", source="plane") is True
    result, _got, provenance = await broker.wait(rid, timeout=1.0)
    assert result is ApprovalResult.APPROVED
    assert provenance is not None
    assert provenance.operator_id == "alice"
    assert provenance.source == "plane"


async def test_wait_timeout_has_no_provenance() -> None:
    broker = ApprovalBroker()
    rid = broker.submit(_grant(), reason="high risk")
    result, _released_grant, provenance = await broker.wait(rid, timeout=0.01)
    assert result is ApprovalResult.EXPIRED
    assert provenance is None
