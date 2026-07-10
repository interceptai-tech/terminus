"""FastAPI route and orchestration for Terminus interception."""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi_limiter import FastAPILimiter  # type: ignore[import-untyped]
from fastapi_limiter.depends import RateLimiter  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, field_validator

from terminus.audit.audit_logger import AuditLogger, get_audit_logger
from terminus.auth.dependency import authenticate
from terminus.auth.registry import get_registry
from terminus.config.settings import get_settings
from terminus.observability.metrics import (
    record_rate_limiter_unavailable,
    record_request,
    record_signature_match,
    record_velocity_anomaly,
    record_would_deny,
)
from terminus.parser.sql_parser import ParsedSQL, parse_sql
from terminus.policy.graduated import resolve_enforcement_mode, soften_if_observing
from terminus.policy.policy_engine import PolicyDecision, PolicyEngine, get_policy_engine
from terminus.remediation.remediation import Remediation, build_remediation
from terminus.signature.emitter import SignatureEmitter, get_signature_emitter
from terminus.signature.facts import RoleResolver, SignatureFacts, to_signature_facts
from terminus.signature.gate import should_emit_signature
from terminus.signature.matcher import evaluate_match
from terminus.signature.signature import build_signature, fingerprint_for
from terminus.signature.store import SignatureStore, get_signature_store
from terminus.velocity.classifier import extraction_class
from terminus.velocity.tracker import VelocityTrackers, get_velocity_trackers

router = APIRouter(tags=["intercept"])

_log = structlog.get_logger("terminus.ratelimit")
_sig_log = structlog.get_logger("terminus.signature.pipeline")

# Built lazily so TERMINUS_RATE_LIMIT_PER_MINUTE is read after env is applied.
_rate_limiter: _SafeRateLimiter | None = None


class _SafeRateLimiter(RateLimiter):  # type: ignore[misc]  # RateLimiter is untyped (Any)
    """RateLimiter without fastapi-limiter's fragile route-index scan.

    The upstream __call__ iterates request.app.routes to disambiguate multiple
    limiters on one path, but that loop assumes every route exposes `.path` and
    raises AttributeError on newer FastAPI router objects (_IncludedRouter). We
    have exactly one limiter per route, so a fixed key index of 0 is correct.
    """

    async def __call__(self, request: Request, response: Response) -> None:
        if not FastAPILimiter.redis:
            return
        identifier = self.identifier or FastAPILimiter.identifier
        callback = self.callback or FastAPILimiter.http_callback
        rate_key = await identifier(request)
        key = f"{FastAPILimiter.prefix}:{rate_key}:0"
        pexpire = await self._check(key)
        if pexpire != 0:
            await callback(request, response, pexpire)


async def agent_identifier(request: Request) -> str:
    """Rate-limit key: the trusted agent id when authenticated, else self-asserted.

    When a JWT was verified, authenticate() set request.state.trusted_agent_id and
    we key on it (the X-Agent-ID header is ignored). Otherwise fall back to the
    self-asserted header / agent_id query / client host.
    """
    trusted = getattr(request.state, "trusted_agent_id", None)
    if trusted:
        agent: str | None = trusted
    else:
        agent = request.headers.get("X-Agent-ID") or request.query_params.get("agent_id")
        if not agent:
            client = request.client
            agent = client.host if client else "anonymous"
    path = request.scope.get("path", "")
    return f"{agent}:{path}"


def _get_rate_limiter() -> _SafeRateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        settings = get_settings()
        _rate_limiter = _SafeRateLimiter(
            times=settings.rate_limit_per_minute,
            minutes=1,
            identifier=agent_identifier,
        )
    return _rate_limiter


async def enforce_rate_limit(request: Request, response: Response) -> None:
    """Apply the per-agent rate limit, failing OPEN if the limiter is down.

    Rate limiting is a guardrail, not the core circuit breaker. If Redis is
    unreachable (so FastAPILimiter never initialized), or the limiter itself
    malfunctions, we log and allow the request through to SQL validation rather
    than denying all traffic. A real 429 (HTTPException) is intentional and
    propagates.
    """
    if not FastAPILimiter.redis:
        _log.warning("rate_limit_skipped", reason="limiter_not_initialized")
        record_rate_limiter_unavailable()
        return
    try:
        await _get_rate_limiter()(request, response)
    except HTTPException:
        raise  # the 429 "Too Many Requests" is the intended outcome
    except Exception as exc:  # never let a limiter bug 500 the core breaker
        _log.warning("rate_limit_error", error=exc.__class__.__name__)
        record_rate_limiter_unavailable()


# GAPS L1: metadata is free-form context whose sorted keys land in every audit
# event. Bound its SHAPE (the body-size middleware bounds its bytes) so a
# pathological object cannot inflate audit lines. The object itself is depth 1;
# one nesting level is allowed; anything at depth 3 is rejected. 64/2 is far
# above legitimate use (the dogfood agent sends 2-3 flat keys).
METADATA_MAX_KEYS = 64
METADATA_MAX_DEPTH = 2


def _check_metadata_depth(value: object, depth: int) -> None:
    if isinstance(value, dict | list):
        if depth > METADATA_MAX_DEPTH:
            raise ValueError(f"metadata nests deeper than {METADATA_MAX_DEPTH} levels")
        items = value.values() if isinstance(value, dict) else value
        for item in items:
            _check_metadata_depth(item, depth + 1)


class InterceptRequest(BaseModel):
    """Request body for the /intercept endpoint."""

    sql: str = Field(min_length=1, max_length=131_072)
    agent_id: str | None = Field(default=None, max_length=256)
    dialect: str | None = Field(default=None, max_length=64)
    request_id: str = Field(default_factory=lambda: str(uuid4()), max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _bound_metadata_shape(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > METADATA_MAX_KEYS:
            raise ValueError(
                f"metadata has {len(value)} top-level keys; " f"maximum is {METADATA_MAX_KEYS}"
            )
        for item in value.values():
            _check_metadata_depth(item, depth=2)
        return value


class InterceptResponse(BaseModel):
    """Decision body returned by Terminus."""

    decision: str  # "allow", "deny", "review"
    request_id: str
    operation: str
    tables: list[str]
    risk_score: float
    policy_id: str | None = None
    reason: str
    risk_reasons: list[str] = Field(default_factory=list)
    remediation: Remediation | None = None


@router.post(
    "",
    response_model=InterceptResponse,
    dependencies=[Depends(authenticate), Depends(enforce_rate_limit)],
)
async def intercept(
    request: Request,
    payload: InterceptRequest,
    policy_engine: PolicyEngine = Depends(get_policy_engine),  # noqa: B008
    audit_logger: AuditLogger = Depends(get_audit_logger),  # noqa: B008
    signature_emitter: SignatureEmitter = Depends(get_signature_emitter),  # noqa: B008
    signature_store: SignatureStore = Depends(get_signature_store),  # noqa: B008
    velocity_trackers: VelocityTrackers = Depends(get_velocity_trackers),  # noqa: B008
) -> JSONResponse | InterceptResponse:
    """Parse, evaluate, remediate, and audit an intercepted SQL statement."""

    trusted_agent_id: str | None = getattr(request.state, "trusted_agent_id", None)
    # When a JWT was verified, its sub is authoritative and overrides any
    # self-asserted id. On the permissive legacy path (no token) we fall back to
    # the request body's self-asserted agent_id, today's behavior.
    effective_agent_id = trusted_agent_id if trusted_agent_id is not None else payload.agent_id
    agent_authenticated = trusted_agent_id is not None

    settings = get_settings()
    # Offload the CPU-bound parse to a worker thread. The size cap bounds the
    # worst-case parse; to_thread keeps the (single-worker) event loop responsive
    # to other requests during it, since CPython releases the GIL every few ms.
    # Costs ~25us on a normal query, and the in-process latency gate calls
    # parse_sql directly, so this never touches the p99 budget.
    parsed_sql: ParsedSQL = await asyncio.to_thread(
        parse_sql,
        payload.sql,
        # payload.dialect is attacker-controlled: it may drive PARSE syntax (falls
        # back to it only when no deployment dialect is configured) but must NEVER
        # drive identifier normalization, which whitelist/policy matching depends
        # on. normalize_dialect pins normalization to the trusted deployment
        # dialect only, closing the whitelist-bypass where a case-insensitive
        # payload.dialect folds a quoted case-variant identifier onto a distinct
        # whitelisted object.
        dialect=settings.sql_dialect or payload.dialect,
        normalize_dialect=settings.sql_dialect,
        # Velocity is included so standalone-velocity mode (signatures off) still
        # gets a full-fidelity fingerprint, instead of a coarsened one.
        collect_signature_facts=settings.signatures_enabled
        or settings.signature_matching_enabled
        or settings.velocity_enabled,
        max_length=settings.max_sql_length,
    )

    decision: PolicyDecision = policy_engine.evaluate(parsed_sql, agent_id=effective_agent_id)

    # Graduated autonomy (per-agent observe). Runs immediately after the engine so
    # the guardrails below see the effective decision. Softening keys on the
    # JWT-verified identity only; self-asserted ids always get enforce.
    enforcement_mode = resolve_enforcement_mode(
        settings=settings,
        registry=get_registry(),
        agent_id=effective_agent_id,
        agent_authenticated=agent_authenticated,
    )
    decision, would_deny, would_deny_reason_code = soften_if_observing(decision, enforcement_mode)
    if would_deny and would_deny_reason_code is not None:
        parsed_sql.risk_reasons.append(f"would_deny:{would_deny_reason_code}")
        record_would_deny(would_deny_reason_code, parsed_sql.operation)

    # Compute the name-free fingerprint ONCE if any consumer (signature matching or
    # F9 velocity) needs it. Fail-safe: a fingerprint error degrades both to "no
    # signal" and never changes the decision or 500s the request.
    fingerprint: str | None = None
    sig_facts: SignatureFacts | None = None
    if settings.signature_matching_enabled or settings.velocity_enabled:
        try:
            resolver = RoleResolver(policy_engine.whitelist)
            fingerprint, sig_facts, _technique = fingerprint_for(parsed_sql, resolver)
        except Exception as exc:  # never let fingerprinting affect the response
            _sig_log.warning("fingerprint_failed", error=exc.__class__.__name__)

    # Signature matching (Phase 2A). Reuses the fingerprint above.
    if settings.signature_matching_enabled and fingerprint is not None:
        try:
            result = evaluate_match(
                fingerprint,
                decision,
                signature_store,
                # Per-agent trust gates guardrail enforcement: necessary but not
                # sufficient (the flag alone no longer enables enforcement).
                enforce_enabled=settings.signature_enforce_enabled
                and enforcement_mode == "enforce",
            )
            if result.matched and result.record is not None:
                record_signature_match(result.record.mode, result.record.severity)
                if "signature_match" not in parsed_sql.risk_reasons:
                    parsed_sql.risk_reasons.append("signature_match")
                decision = result.decision
        except Exception as exc:  # never let matching affect the response
            _sig_log.warning("signature_match_failed", error=exc.__class__.__name__)

    # F9 velocity check. Behavioral guardrail: observe by default; under enforce it
    # only escalates an allow to deny, never overrides an existing deny, and ONLY
    # for an authenticated (JWT-verified) agent identity. Unauthenticated /
    # self-asserted / anonymous traffic is still observed (flagged with
    # velocity_anomaly + metric) but can never be denied, because that identity is
    # attacker-controlled: without this gate, an attacker could spoof a victim's
    # agent_id (or flood the shared "unknown" bucket) to push the counter over
    # threshold and get the victim's, or another client's, legitimate queries
    # denied -- a cross-agent denial of service. Fail-open: any error degrades to
    # no signal and never 500s or blocks.
    if settings.velocity_enabled and fingerprint is not None and sig_facts is not None:
        try:
            class_key = extraction_class(sig_facts, fingerprint)
            # Route to the trust-isolated pool: authenticated traffic is tracked and
            # enforced in the auth pool (keyed by the JWT-verified id); untrusted
            # traffic goes to the observe-only unauth pool. Separate bounded pools
            # mean an unauth flood cannot evict or reset an authenticated agent's
            # enforcement counter, and a spoofed id cannot poison an auth bucket.
            tracker = velocity_trackers.auth if agent_authenticated else velocity_trackers.unauth
            identity = effective_agent_id or "anon"
            if class_key is not None and tracker.record_and_check(identity, class_key):
                if "velocity_anomaly" not in parsed_sql.risk_reasons:
                    parsed_sql.risk_reasons.append("velocity_anomaly")
                # Label the metric by the ACTUAL outcome (did this anomaly cause a
                # velocity deny), not the posture flag: an observe-only anomaly on
                # unauthenticated traffic, or one on an already-denied query, is
                # enforced=false. Also gated by per-agent trust: an observe-mode
                # agent's traffic is never denied by this guardrail either, same as
                # the signature escalation above.
                will_enforce = (
                    settings.velocity_enforce_enabled
                    and agent_authenticated
                    and decision.action == "allow"
                    and enforcement_mode == "enforce"
                )
                record_velocity_anomaly(enforced=will_enforce)
                if will_enforce:
                    decision = PolicyDecision(
                        action="deny",
                        reason=(
                            "Query velocity for this agent exceeded the configured "
                            "threshold, a possible data-extraction pattern."
                        ),
                        reason_code="velocity_anomaly",
                    )
        except Exception as exc:  # never let the velocity check affect the response
            _sig_log.warning("velocity_check_failed", error=exc.__class__.__name__)

    # Offloaded too: suggest_rewrite re-parses SQL (rewrite + revalidation) on a
    # wildcard-column deny, so keep that parsing off the event loop and honor the
    # configured cap. Only fires for that one deny path.
    suggested_sql: str | None = await asyncio.to_thread(
        policy_engine.suggest_rewrite,
        parsed_sql,
        payload.sql,
        decision,
        agent_id=effective_agent_id,
        # TRUSTED deployment dialect only (never payload.dialect): the rewrite
        # re-parses and re-normalizes the raw SQL, and that fold must match the
        # same dialect the whitelist/policy config was normalized under, or the
        # rewritten table/column names silently stop matching `restrictions`.
        dialect=settings.sql_dialect,
        max_length=settings.max_sql_length,
    )

    remediation: Remediation | None = build_remediation(
        decision, parsed_sql, suggested_sql=suggested_sql
    )

    # Emit Prometheus counters. reason_code is low-cardinality on purpose;
    # the smuggling flag comes straight from the parser's AST inspection.
    record_request(
        action=decision.action,
        reason_code=decision.reason_code,
        operation=parsed_sql.operation,
        smuggling=parsed_sql.security_flags.has_smuggling_pattern,
        agent_id=effective_agent_id,
    )

    audit_logger.log_decision(
        request_id=payload.request_id,
        sql=payload.sql,
        agent_id=effective_agent_id,
        parsed_sql=parsed_sql,
        decision=decision,
        remediation_present=remediation is not None,
        metadata=payload.metadata,
        rewrite_suggested=suggested_sql is not None,
        agent_authenticated=agent_authenticated,
        enforcement_mode=enforcement_mode,
        would_deny=would_deny,
        would_deny_reason_code=would_deny_reason_code,
    )

    # Signature emission is telemetry. The ENTIRE pipeline, including the gate
    # call, is wrapped so a bug here can never change the decision or 500 the
    # request. The expensive build/emit only runs when the gate passes; the cheap
    # parser fact collection already ran above (gated by signatures_enabled).
    try:
        # would_deny: observe-mode softened violations are the evidence the operator
        # reviews before promotion, so they must emit even though the (softened)
        # decision is an allow; still inside this fail-safe try and name-free by
        # construction, so nothing new can leak. Would-deny evidence respects the
        # signatures master switch: off means zero signature telemetry, and it
        # avoids emitting coarsened facts when the collectors are off.
        if should_emit_signature(decision, parsed_sql, settings) or (
            would_deny and settings.signatures_enabled
        ):
            resolver = RoleResolver(policy_engine.whitelist)
            facts = to_signature_facts(parsed_sql, resolver)
            signature_emitter.emit(build_signature(facts, decision))
    except Exception as exc:  # never let signature work affect the response
        _sig_log.warning("signature_emit_failed", error=exc.__class__.__name__)

    response = InterceptResponse(
        decision=decision.action,
        request_id=payload.request_id,
        operation=parsed_sql.operation,
        tables=parsed_sql.tables,
        risk_score=parsed_sql.risk_score,
        policy_id=decision.policy_id,
        reason=decision.reason,
        risk_reasons=parsed_sql.risk_reasons,
        remediation=remediation,
    )

    if decision.action == "allow":
        return response

    headers = {}
    if remediation is not None:
        headers["X-Terminus-Remediation"] = remediation.header_value

    return JSONResponse(
        status_code=403,
        content=response.model_dump(mode="json"),
        headers=headers,
    )
