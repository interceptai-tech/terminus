"""MCP server: composition root and the query/execute tool logic.

ToolService holds all branching (testable without the MCP SDK). build_server() wires
it to FastMCP. The agent identity is bound at startup from settings and validated
against the registry (one server per agent for the reference PEP).
"""

from __future__ import annotations

from typing import Any

import structlog

from terminus.audit.audit_logger import AuditLogger
from terminus.auth.registry import AgentRegistry, get_registry
from terminus.config.settings import TerminusSettings, get_settings
from terminus.mcp.approvals import ApprovalBroker, ApprovalResult
from terminus.mcp.audit import record_tool_decision
from terminus.mcp.decider import decide
from terminus.mcp.executor import Executor
from terminus.mcp.grants import Allowed, Denied, NeedsApproval
from terminus.observability.metrics import record_would_deny
from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.graduated import resolve_enforcement_mode
from terminus.policy.policy_engine import PolicyDecision, PolicyEngine, get_policy_engine

_log = structlog.get_logger("terminus.mcp")


def resolve_agent_id(settings: TerminusSettings, registry: AgentRegistry) -> str:
    """Return the configured MCP agent id, or raise if missing / not active."""
    agent_id = settings.mcp_agent_id
    if not agent_id:
        raise RuntimeError("TERMINUS_MCP_AGENT_ID must be set to run the MCP server")
    if not registry.is_active(agent_id):
        raise RuntimeError(f"MCP agent id {agent_id!r} is not an active registered agent")
    return agent_id


class ToolService:
    """The query/execute tool logic. Pure of the MCP SDK, so it is unit-testable."""

    def __init__(
        self,
        *,
        settings: TerminusSettings,
        policy_engine: PolicyEngine,
        executor: Executor,
        broker: ApprovalBroker,
        audit_logger: AuditLogger,
        agent_id: str,
    ) -> None:
        self._settings = settings
        self._engine = policy_engine
        self._executor = executor
        self._broker = broker
        self._audit = audit_logger
        self._agent_id = agent_id

    async def query(self, sql: str) -> dict[str, Any]:
        return await self._handle(sql, expected="read", read=True, tool="query")

    async def execute(self, sql: str) -> dict[str, Any]:
        return await self._handle(sql, expected="write", read=False, tool="execute")

    async def _handle(self, sql: str, *, expected: str, read: bool, tool: str) -> dict[str, Any]:
        from uuid import uuid4

        request_id = uuid4().hex
        # Resolved once per call, from the boot-validated MCP agent identity (never
        # anything caller-supplied): agent_authenticated=True because mcp_agent_id
        # is validated against the registry at server startup (resolve_agent_id),
        # not asserted per-request. See terminus.policy.graduated.
        trust_level = resolve_enforcement_mode(
            settings=self._settings,
            registry=get_registry(),
            agent_id=self._agent_id,
            agent_authenticated=True,
        )
        outcome = await decide(
            sql=sql,
            agent_id=self._agent_id,
            request_id=request_id,
            expected=expected,  # type: ignore[arg-type]
            policy_engine=self._engine,
            settings=self._settings,
            trust_level=trust_level,
        )

        # Promotion-evidence metric, mirrored from the HTTP router
        # (interceptor/router.py): the MCP surface must count would-be denials
        # too, or an MCP-only deployment's terminus_would_deny_total dashboard
        # reads zero forever even while the audit trail records evidence.
        # Purely additive telemetry: never gates or alters the response below.
        if outcome.would_deny and outcome.would_deny_reason_code is not None:
            record_would_deny(outcome.would_deny_reason_code, outcome.parsed.operation)

        if isinstance(outcome, Denied):
            audit_err = await self._audit_or_error(
                outcome.parsed,
                outcome.decision,
                sql,
                request_id,
                tool,
                "denied",
                trust_level,
                outcome.would_deny,
                outcome.would_deny_reason_code,
            )
            if audit_err is not None:
                return audit_err
            body: dict[str, Any] = {
                "status": "denied",
                "reason": outcome.reason,
                "reason_code": outcome.reason_code,
                "request_id": request_id,
            }
            if outcome.remediation is not None:
                body["remediation"] = outcome.remediation.model_dump(mode="json")
            return body

        if isinstance(outcome, NeedsApproval):
            self._broker.submit(outcome.grant, outcome.reason)
            audit_err = await self._audit_or_error(
                outcome.parsed,
                outcome.decision,
                sql,
                request_id,
                tool,
                "pending_approval",
                trust_level,
                outcome.would_deny,
                outcome.would_deny_reason_code,
            )
            if audit_err is not None:
                return audit_err
            result, grant = await self._broker.wait(
                request_id, timeout=float(self._settings.mcp_approval_timeout_seconds)
            )
            if result is not ApprovalResult.APPROVED or grant is None:
                status = (
                    "approval_denied" if result is ApprovalResult.DENIED else "approval_expired"
                )
                audit_err = await self._audit_or_error(
                    outcome.parsed,
                    outcome.decision,
                    sql,
                    request_id,
                    tool,
                    status,
                    trust_level,
                    outcome.would_deny,
                    outcome.would_deny_reason_code,
                )
                if audit_err is not None:
                    return audit_err
                return {
                    "status": status,
                    "reason": f"High-risk write was not approved ({result.value}).",
                    "request_id": request_id,
                }
            # Audit BEFORE executing: a statement must never run without its
            # decision already in the tamper-evident chain (fail-closed). The
            # audit event records the decision, not the execution outcome.
            audit_err = await self._audit_or_error(
                outcome.parsed,
                outcome.decision,
                sql,
                request_id,
                tool,
                "approved",
                trust_level,
                outcome.would_deny,
                outcome.would_deny_reason_code,
            )
            if audit_err is not None:
                return audit_err
            try:
                exec_result = await self._executor.run(grant, read=read)
            except Exception as exc:
                return self._execution_error(exc, request_id)
            return {"status": "ok", "row_count": exec_result.row_count, "request_id": request_id}

        assert isinstance(outcome, Allowed)
        # Same audit-before-execute fail-closed invariant as the approved path.
        audit_err = await self._audit_or_error(
            outcome.parsed,
            outcome.decision,
            sql,
            request_id,
            tool,
            None,
            trust_level,
            outcome.would_deny,
            outcome.would_deny_reason_code,
        )
        if audit_err is not None:
            return audit_err
        try:
            exec_result = await self._executor.run(outcome.grant, read=read)
        except Exception as exc:
            return self._execution_error(exc, request_id)
        if read:
            return {
                "status": "ok",
                "rows": exec_result.rows,
                "row_count": exec_result.row_count,
                "request_id": request_id,
            }
        return {"status": "ok", "row_count": exec_result.row_count, "request_id": request_id}

    def _execution_error(self, exc: Exception, request_id: str) -> dict[str, Any]:
        """Generic error body for a failed execution; never leaks the driver error.

        asyncpg exceptions routinely embed the failing statement text, and the MCP
        tool dispatcher returns str(exception) verbatim to the untrusted client, so
        a raw DB error must never escape this method. Log the exception CLASS only
        (never str(exc), never the statement) per the repo's logging rules.
        """
        _log.warning(
            "mcp_execution_failed",
            error_class=exc.__class__.__name__,
            request_id=request_id,
        )
        return {
            "status": "error",
            "reason": "statement execution failed",
            "reason_code": "execution_error",
            "request_id": request_id,
        }

    async def _audit_or_error(
        self,
        parsed: ParsedSQL,
        decision: PolicyDecision,
        sql: str,
        request_id: str,
        tool: str,
        approval_status: str | None,
        enforcement_mode: str,
        would_deny: bool,
        would_deny_reason_code: str | None,
    ) -> dict[str, Any] | None:
        """Record the decision in the audit chain; on failure, fail closed.

        Returns None on success, or a generic error body the caller must return
        WITHOUT executing anything: no statement may run unless its decision is
        already in the audit chain, and no audit exception may reach the client.

        ``parsed``/``decision`` are the ACTUAL parse and decision decide() made
        for this call, not a re-derived guess: re-parsing and re-evaluating here
        used to risk recording a decision that disagreed with what the client was
        actually told (e.g. a wrong-tool deny returned to the client, but an
        "allow" from re-evaluating the same SQL against the wrong-tool check's own
        engine path). Threading the real outcome through removes that
        possibility, and the double parse/evaluate it used to cost.

        ``enforcement_mode``/``would_deny``/``would_deny_reason_code`` are the
        graduated-autonomy v3 evidence resolved and threaded by ``_handle``.
        """
        try:
            self._audit_call(
                parsed,
                decision,
                sql,
                request_id,
                tool,
                approval_status,
                enforcement_mode,
                would_deny,
                would_deny_reason_code,
            )
        except Exception as exc:
            _log.warning(
                "mcp_audit_failed",
                error_class=exc.__class__.__name__,
                request_id=request_id,
            )
            return {
                "status": "error",
                "reason": "audit unavailable",
                "reason_code": "audit_error",
                "request_id": request_id,
            }
        return None

    def _audit_call(
        self,
        parsed: ParsedSQL,
        decision: PolicyDecision,
        sql: str,
        request_id: str,
        tool: str,
        approval_status: str | None,
        enforcement_mode: str,
        would_deny: bool,
        would_deny_reason_code: str | None,
    ) -> None:
        record_tool_decision(
            audit_logger=self._audit,
            request_id=request_id,
            sql=sql,
            agent_id=self._agent_id,
            parsed_sql=parsed,
            decision=decision,
            tool=tool,
            approval_status=approval_status,
            enforcement_mode=enforcement_mode,
            would_deny=would_deny,
            would_deny_reason_code=would_deny_reason_code,
        )


def build_server() -> Any:
    """Wire ToolService to a FastMCP server. SDK-specific; verify against installed mcp."""
    import asyncpg  # type: ignore[import-untyped]
    from mcp.server.fastmcp import FastMCP

    settings = get_settings()
    registry = get_registry()
    agent_id = resolve_agent_id(settings, registry)

    mcp = FastMCP("terminus")
    service_holder: dict[str, ToolService] = {}

    async def _service() -> ToolService:
        if "svc" not in service_holder:
            pool = await asyncpg.create_pool(dsn=settings.mcp_postgres_dsn)
            service_holder["svc"] = ToolService(
                settings=settings,
                policy_engine=get_policy_engine(),
                executor=Executor(_AsyncpgPool(pool)),
                broker=ApprovalBroker(),
                audit_logger=AuditLogger(),
                agent_id=agent_id,
            )
        return service_holder["svc"]

    @mcp.tool()
    async def query(sql: str) -> dict[str, Any]:
        """Run a read-only SELECT, gated by Terminus policy."""
        return await (await _service()).query(sql)

    @mcp.tool()
    async def execute(sql: str) -> dict[str, Any]:
        """Run a write, gated by Terminus policy; high-risk writes need human approval."""
        return await (await _service()).execute(sql)

    return mcp


class _AsyncpgPool:
    """Adapt an asyncpg pool to the executor's ConnectionPool protocol."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def fetch(self, sql: str) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(sql)
        return [dict(r) for r in rows]

    async def execute(self, sql: str) -> str:
        return str(await self._pool.execute(sql))
