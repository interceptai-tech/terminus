"""In-memory human-approval broker for high-risk writes (break-glass).

A held grant is released to the executor ONLY after an operator approves. Timeout and
deny both expire without a grant (fail-closed). In-process/single-instance for the
reference PEP; a shared-store broker for HA is a fast-follow.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from uuid import uuid4

from terminus.mcp.grants import ExecutionGrant


class ApprovalResult(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class _Pending:
    __slots__ = ("grant", "reason", "event", "result")

    def __init__(self, grant: ExecutionGrant, reason: str) -> None:
        self.grant = grant
        self.reason = reason
        self.event = asyncio.Event()
        self.result: ApprovalResult | None = None


class ApprovalBroker:
    """Holds pending high-risk writes awaiting human approval.

    Usage assumptions (MVP, single-instance):

    - **One waiter per request_id.** The server submits a grant and then calls
      ``wait()`` exactly once. Concurrent ``wait()`` calls on the same
      request_id share one pending entry; the first to return (including by
      timeout) pops the entry, orphaning the other waiter and making later
      ``approve``/``deny`` return False.
    - **request_ids are unique.** ``submit()`` with a duplicate request_id
      replaces the previous pending entry.

    Violating either assumption stays fail-closed (no grant is ever released
    without an explicit approve), but it desyncs ``pending()`` and the
    ``approve``/``deny`` return values.
    """

    def __init__(self) -> None:
        self._pending: dict[str, _Pending] = {}

    def submit(self, grant: ExecutionGrant, reason: str) -> str:
        request_id = grant.request_id or uuid4().hex
        self._pending[request_id] = _Pending(grant, reason)
        return request_id

    def pending(self) -> list[str]:
        return list(self._pending)

    def _resolve(self, request_id: str, result: ApprovalResult) -> bool:
        entry = self._pending.get(request_id)
        if entry is None:
            return False
        # First decision wins (compare-and-swap): once resolved, a later
        # approve/deny must NOT flip the result. Without this, deny(rid)
        # followed by approve(rid) before the waiter resumes would overwrite
        # DENIED with APPROVED and leak the grant (fail-closed violation).
        if entry.result is not None:
            return False
        entry.result = result
        entry.event.set()
        return True

    def approve(self, request_id: str) -> bool:
        return self._resolve(request_id, ApprovalResult.APPROVED)

    def deny(self, request_id: str) -> bool:
        return self._resolve(request_id, ApprovalResult.DENIED)

    async def wait(
        self, request_id: str, *, timeout: float
    ) -> tuple[ApprovalResult, ExecutionGrant | None]:
        entry = self._pending.get(request_id)
        if entry is None:
            return ApprovalResult.EXPIRED, None
        try:
            await asyncio.wait_for(entry.event.wait(), timeout=timeout)
        except TimeoutError:
            entry.result = ApprovalResult.EXPIRED
        finally:
            self._pending.pop(request_id, None)
        result = entry.result or ApprovalResult.EXPIRED
        grant = entry.grant if result is ApprovalResult.APPROVED else None
        return result, grant
