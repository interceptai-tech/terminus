"""MCP server: composition root and the query/execute tool logic.

ToolService holds all branching (testable without the MCP SDK). build_server() wires
it to FastMCP. The agent identity is bound at startup from settings and validated
against the registry (one server per agent for the reference PEP).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import httpx
import structlog

from terminus.audit.audit_logger import AuditLogger
from terminus.auth.registry import AgentRegistry, get_registry
from terminus.config.settings import TerminusSettings, get_settings
from terminus.mcp.approvals import ApprovalBroker, ApprovalResult
from terminus.mcp.audit import record_tool_decision
from terminus.mcp.decider import decide
from terminus.mcp.executor import Executor
from terminus.mcp.grants import Allowed, Denied, NeedsApproval
from terminus.observability.metrics import HOLDS_ACTIVE, PLANE_SUBMIT, record_would_deny
from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.graduated import resolve_enforcement_mode
from terminus.policy.policy_engine import PolicyDecision, PolicyEngine, get_policy_engine

# Keeps the non-plane path free of a hard plane import at module load: these
# names are only used for type annotations below (see ToolService.__init__).
if TYPE_CHECKING:
    from terminus.plane.client import PlaneClient
    from terminus.plane.courier import PendingHolds
    from terminus.plane.enrollment import PlaneContext
    from terminus.plane.reveal import RevealLedger

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
        plane_client: PlaneClient | None = None,
        pending_holds: PendingHolds | None = None,
        plane_context: PlaneContext | None = None,
        reveal_ledger: RevealLedger | None = None,
    ) -> None:
        self._settings = settings
        self._engine = policy_engine
        self._executor = executor
        self._broker = broker
        self._audit = audit_logger
        self._agent_id = agent_id
        self._plane_client = plane_client
        self._pending_holds = pending_holds
        self._plane_context = plane_context
        # SAME instance passed to run_courier (see _service() below) -- eviction
        # here and the courier's own drop() on unknown_request both act on one
        # shared RevealLedger, or eviction is a silent no-op on an orphaned copy.
        self._reveal_ledger = reveal_ledger

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
            if len(self._broker.pending()) >= self._settings.mcp_approval_max_holds:
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
                return {
                    "status": "denied",
                    "reason": (
                        "Too many writes are already awaiting human approval; "
                        "retry after pending holds resolve."
                    ),
                    "reason_code": "max_holds_exceeded",
                    "request_id": request_id,
                }
            self._broker.submit(outcome.grant, outcome.reason)
            HOLDS_ACTIVE.set(len(self._broker.pending()))
            if (
                self._plane_client is not None
                and self._pending_holds is not None
                and self._plane_context is not None
            ):
                # Bundle assembly lives INSIDE the try too: if it ever raised, it
                # must degrade like a submit failure (log + fall through to
                # broker.wait) rather than propagating out of _handle and
                # orphaning the grant already submitted to the broker above.
                try:
                    from datetime import UTC, datetime

                    from terminus.plane.bundle import bundle_sha256_of, from_needs_approval

                    reveal_required = (
                        outcome.parsed.risk_score >= self._settings.mcp_approval_reveal_threshold
                    )
                    bundle = from_needs_approval(
                        outcome,
                        tenant_id=self._plane_context.identity.tenant_id,
                        deployment_id=self._plane_context.identity.deployment_id,
                        submitted_at=datetime.now(UTC).isoformat(),
                        reveal_required=reveal_required,
                        sign=self._plane_context.identity.sign,
                    )
                    await self._plane_client.submit_hold(bundle)
                    # Record the digest only after a successful submit: no submit,
                    # no decision to expect, so no map entry to leak.
                    self._pending_holds.put(
                        request_id,
                        sql_sha256=bundle.sql_sha256,
                        bundle_sha256=bundle_sha256_of(
                            bundle.model_dump(exclude={"deployment_signature"})
                        ),
                        reveal_required=reveal_required,
                    )
                    PLANE_SUBMIT.labels(result="ok").inc()
                except (
                    Exception
                ) as exc:  # noqa: BLE001 - best-effort; fail closed via broker timeout
                    PLANE_SUBMIT.labels(result="error").inc()
                    _log.warning(
                        "plane_submit_failed",
                        request_id=request_id,
                        error_class=type(exc).__name__,
                        reason_code="plane_submit_failed",
                    )
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
            result, grant, provenance = await self._broker.wait(
                request_id, timeout=float(self._settings.mcp_approval_timeout_seconds)
            )
            HOLDS_ACTIVE.set(len(self._broker.pending()))
            # provenance is None on a timeout (nobody resolved it, so nobody to
            # attribute); on an explicit deny it is still populated, so audit
            # records who denied it, not just that a timeout mimics a deny.
            operator_id = provenance.operator_id if provenance is not None else None
            approval_source = provenance.source if provenance is not None else None
            if result is not ApprovalResult.APPROVED or grant is None:
                # Evict courier-side hold state: nothing can legitimately arrive
                # for this request_id anymore (a late plane decision hits the
                # courier's unknown_request branch and is acked away -- see
                # courier._dispatch). Fail-closed but not unbounded: without
                # this, an operator who never resolves a hold leaks a
                # PendingHolds entry and any RevealLedger records forever.
                if self._pending_holds is not None:
                    self._pending_holds.pop(request_id)
                if self._reveal_ledger is not None:
                    self._reveal_ledger.drop(request_id)
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
                    operator_id=operator_id,
                    approval_source=approval_source,
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
                operator_id=operator_id,
                approval_source=approval_source,
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
        operator_id: str | None = None,
        approval_source: str | None = None,
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
        ``operator_id``/``approval_source`` are the schema v4 operator-identity
        evidence: who resolved a hold (verified via ``ApprovalProvenance``,
        never client-asserted) and whether it came through the plane or a local
        resolution. Both are None outside the approval path (an immediate
        allow/deny never has a provenance to report).
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
                operator_id,
                approval_source,
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
        operator_id: str | None = None,
        approval_source: str | None = None,
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
            operator_id=operator_id,
            approval_source=approval_source,
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
    background: dict[str, Any] = {}

    async def _service() -> ToolService:
        if "svc" not in service_holder:
            pool = await asyncpg.create_pool(dsn=settings.mcp_postgres_dsn)
            broker = ApprovalBroker()
            audit_logger = AuditLogger()
            plane_client = None
            pending_holds = None
            plane_context = None
            reveal_ledger = None
            if settings.plane_enabled:
                from terminus.plane.client import PlaneClient
                from terminus.plane.courier import PendingHolds, run_courier
                from terminus.plane.enrollment import load_plane_context
                from terminus.plane.nonce import build_seen_nonces_pair
                from terminus.plane.reveal import RevealLedger

                ctx = load_plane_context(settings)
                plane_context = ctx
                http = httpx.AsyncClient(
                    base_url=settings.plane_base_url,
                    timeout=httpx.Timeout(settings.plane_poll_wait_seconds + 10),
                )
                plane_client = PlaneClient(identity=ctx.identity, http=http)
                pending_holds = PendingHolds()
                # ONE shared instance, passed BY REFERENCE to both run_courier
                # below and ToolService further down: the courier drops a
                # record on unknown_request, and ToolService._handle drops one
                # on local timeout/deny. Eviction on a different RevealLedger
                # object is a silent no-op, so this must not be constructed
                # twice.
                reveal_ledger = RevealLedger()
                # Empty TERMINUS_PLANE_NONCE_PATH keeps today's in-memory-only
                # behavior; a non-empty path backs both stores with a disk
                # journal (see docs/configuration.md) so replay protection
                # survives a process restart.
                decision_nonces, reveal_nonces = build_seen_nonces_pair(
                    settings.plane_nonce_path, ttl_seconds=settings.plane_nonce_ttl_seconds
                )
                # Lives for the process lifetime: a stdio MCP server runs until the
                # transport closes, matching the process-scoped broker and audit
                # chain (see mcp/__main__.py; the courier is NOT started there).
                # Same AuditLogger instance as ToolService below (constructed
                # once above): reveal_served/reveal_rejected land on the same
                # process-scoped chain as decision/trust-change events, so
                # production always audits reveals, never just unit tests that
                # explicitly wire one up.
                courier_task = asyncio.create_task(
                    run_courier(
                        client=plane_client,
                        broker=broker,
                        context=ctx,
                        pending=pending_holds,
                        poll_wait=settings.plane_poll_wait_seconds,
                        poll_batch=settings.plane_poll_batch,
                        seen_nonces=decision_nonces,
                        reveal_ledger=reveal_ledger,
                        reveal_nonces=reveal_nonces,
                        audit=audit_logger,
                    )
                )

                def _courier_done(t: asyncio.Task[None]) -> None:
                    # run_courier is fail-closed and never raises out of its own
                    # loop, so a non-cancelled exception here means the task died
                    # some other way (e.g. a bug). Log it: a silently-dead courier
                    # otherwise looks identical to a healthy one that is simply idle.
                    if t.cancelled():
                        return
                    exc = t.exception()
                    if exc is not None:
                        _log.warning(
                            "plane_courier_exited",
                            error_class=type(exc).__name__,
                            reason_code="plane_courier_exited",
                        )

                courier_task.add_done_callback(_courier_done)
                background["courier"] = courier_task
            service_holder["svc"] = ToolService(
                settings=settings,
                policy_engine=get_policy_engine(),
                executor=Executor(_AsyncpgPool(pool)),
                broker=broker,
                audit_logger=audit_logger,
                agent_id=agent_id,
                plane_client=plane_client,
                pending_holds=pending_holds,
                plane_context=plane_context,
                reveal_ledger=reveal_ledger,
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
