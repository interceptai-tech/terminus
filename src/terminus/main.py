"""FastAPI entry point for the Terminus sidecar with lifespan management."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse, urlunparse

import structlog
from fastapi import FastAPI, Request, Response
from fastapi_limiter import FastAPILimiter  # type: ignore[import-untyped]
from redis.asyncio import Redis  # type: ignore[import-untyped]
from starlette.middleware.base import BaseHTTPMiddleware

from terminus.audit.audit_logger import configure_logging, emit_shutdown_checkpoint
from terminus.auth.registry import get_registry
from terminus.config.governance import get_governance_manager, run_config_poll_loop
from terminus.config.settings import assert_known_dialect, assert_production_secrets, get_settings
from terminus.config.worker_guard import assert_single_worker
from terminus.interceptor.router import router as interceptor_router
from terminus.observability.metrics import (
    BUILD_INFO,
    MetricsHandler,
    record_rate_limiter_unavailable,
)
from terminus.policy.policy_engine import get_policy_engine
from terminus.signature.outbound import build_outbound_shipper, get_outbound_buffer
from terminus.signature.store import get_signature_store
from terminus.signature.update_client import build_update_client, run_poll_loop


def _safe_redis_target(url: str) -> str:
    """Return the Redis URL with any user:password stripped, for safe logging.

    A connection URL can embed credentials (redis://user:secret@host); never
    write those to structured logs that may be shipped to an aggregator.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        netloc = host if parsed.port is None else f"{host}:{parsed.port}"
        return urlunparse(parsed._replace(netloc=netloc))
    except ValueError:
        return "redis://<unparseable>"


class ContextMiddleware(BaseHTTPMiddleware):
    """Binds request_id to the structlog context for every request.

    agent_id is intentionally NOT bound here: it is self-asserted (untrusted)
    until the authenticate dependency verifies it. The authoritative agent_id is
    bound by the audit logger from the verified/effective identity.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        request_id = request.headers.get("X-Request-ID", str(id(request)))
        with structlog.contextvars.bound_contextvars(request_id=request_id):
            response: Response = await call_next(request)
            return response


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_bytes`` before they are JSON-parsed.

    Pure ASGI so it runs before FastAPI reads and decodes the body. It rejects on
    an over-limit ``Content-Length`` up front, and also buffers the body (bounded
    to ``max_bytes``) so a missing or lying ``Content-Length`` cannot smuggle a
    huge payload past it; over-limit bodies get a 413. This is the app-layer memory
    backstop. The Pydantic ``sql`` field cap is a separate, later schema check (a
    422), and a hard network-layer limit still belongs at the reverse proxy.
    """

    def __init__(self, app: Any, max_bytes: int) -> None:
        self._app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length" and value.isdigit() and int(value) > self._max_bytes:
                await self._reject(send)
                return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            more_body = message.get("more_body", False)
            if len(body) > self._max_bytes:
                await self._reject(send)
                return

        buffered = bytes(body)
        replayed = False

        async def replay() -> dict[str, Any]:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": buffered, "more_body": False}

        await self._app(scope, replay, send)

    @staticmethod
    async def _reject(send: Any) -> None:
        payload = b'{"detail":"Request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage Redis connection for rate limiting and warm caches.

    Redis backs the rate limiter only, which is a guardrail rather than the core
    circuit breaker. If Redis is unreachable we log and start anyway with rate
    limiting disabled (fail open), so a Redis outage never takes the SQL
    protection offline.
    """
    configure_logging()
    log = structlog.get_logger("terminus.startup")
    settings = get_settings()

    # Fail fast: never boot a non-development environment with a publicly-known
    # default secret (forgeable audit chain / spoofable identity). Raising here
    # aborts uvicorn startup loudly instead of running silently insecure.
    assert_production_secrets(settings)
    assert_known_dialect(settings)
    assert_single_worker(settings)

    redis = None
    try:
        redis = Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        await FastAPILimiter.init(redis)
        log.info("rate_limiter_initialized", redis_target=_safe_redis_target(settings.redis_url))
    except Exception as exc:  # degrade gracefully on any Redis failure
        # Log the exception type, not str(exc), to avoid leaking a target/URL.
        log.warning(
            "rate_limiter_unavailable",
            error=exc.__class__.__name__,
            redis_target=_safe_redis_target(settings.redis_url),
            effect="rate limiting disabled (fail open)",
        )
        record_rate_limiter_unavailable()
        # Guarantee the request-time guard fails open: init() may have set
        # FastAPILimiter.redis before script_load raised.
        FastAPILimiter.redis = None
        if redis is not None:
            await redis.close()
            redis = None

    get_policy_engine()  # Warm policy cache
    registry = get_registry()  # Warm agent registry
    if settings.require_auth and not registry.agents:
        log.warning(
            "auth_required_but_registry_empty",
            detail="TERMINUS_REQUIRE_AUTH is on but the agent registry is empty or missing; "
            "all authenticated requests will be rejected until agents are registered",
            registry_path=str(settings.agent_registry_path),
        )

    # Warm the governance config (policy + whitelist + registry) once, and start a
    # poll loop only when hot-reload is enabled. Mirrors the signature poller.
    governance_manager = get_governance_manager()  # builds the initial snapshot
    config_poll_task: asyncio.Task[None] | None = None
    if settings.config_reload_interval > 0:
        config_poll_task = asyncio.create_task(
            run_config_poll_loop(governance_manager, settings.config_reload_interval)
        )

    # Warm the signature store at startup (off the request path) and optionally
    # start a background poll. Think of this like a config daemon: load the
    # ruleset once before serving traffic, then keep it fresh in the background.
    signature_poll_task: asyncio.Task[None] | None = None
    update_client = build_update_client(settings, get_signature_store())
    if update_client is not None:
        await update_client.refresh()  # warm the store once at startup
        if settings.signature_poll_interval > 0:
            signature_poll_task = asyncio.create_task(
                run_poll_loop(update_client, settings.signature_poll_interval)
            )

    signature_outbound_task: asyncio.Task[None] | None = None
    if settings.signature_outbound_enabled and settings.signature_hub_ingest_url:
        outbound_shipper = build_outbound_shipper(settings, get_outbound_buffer())
        if outbound_shipper is not None:
            signature_outbound_task = asyncio.create_task(outbound_shipper.run())

    yield

    # Cleanup
    emit_shutdown_checkpoint()  # capture the audit chain head before the process exits
    if config_poll_task is not None:
        config_poll_task.cancel()
    if signature_outbound_task is not None:
        signature_outbound_task.cancel()
    if signature_poll_task is not None:
        signature_poll_task.cancel()
    if redis is not None:
        await FastAPILimiter.close()
        await redis.close()


def create_app() -> FastAPI:
    """Create configured FastAPI application using settings."""
    settings = get_settings()

    # GAPS M5: in hardened environments the interactive API surface is recon
    # (full schema, version, endpoints), so all three generated URLs go away:
    # /docs and /redoc are just UIs, /openapi.json is the actual leak.
    disable_docs = bool(settings.disable_docs)
    application = FastAPI(
        title="Terminus",
        version="0.1.0",
        description="Circuit breaker for autonomous AI agent database access.",
        lifespan=lifespan,
        docs_url=None if disable_docs else "/docs",
        redoc_url=None if disable_docs else "/redoc",
        openapi_url=None if disable_docs else "/openapi.json",
    )

    application.add_middleware(ContextMiddleware)
    # Added last so it is the OUTERMOST middleware: reject oversized bodies before
    # anything reads them.
    application.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    application.include_router(interceptor_router, prefix="/intercept")

    # Stamp build info so dashboards can pin the running version/environment.
    BUILD_INFO.labels(version=application.version, environment=settings.environment).set(1)

    @application.get("/metrics")
    async def metrics() -> Response:
        """Prometheus scrape endpoint (text exposition format)."""
        return await MetricsHandler.get_metrics()

    @application.get("/")
    async def root() -> dict[str, str]:
        """Root endpoint with helpful links."""
        links = {
            "message": "Terminus is running",
            "health": "/health",
            "intercept": "/intercept",
        }
        if not disable_docs:
            # Omitted when disabled: a dangling link would both 404 and confirm
            # the docs exist.
            links["docs"] = "/docs"
        return links

    @application.get("/health")
    async def health_check() -> dict[str, str]:
        """Basic health check endpoint."""
        return {
            "status": "ok",
            "service": "terminus",
            "environment": settings.environment,
        }

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "terminus.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level.lower(),
    )
