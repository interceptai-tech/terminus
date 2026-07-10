"""FastAPI dependency that authenticates an agent from a Bearer JWT."""

from __future__ import annotations

import structlog
from fastapi import HTTPException, Request, status

from terminus.auth.registry import get_registry
from terminus.auth.tokens import verify_token
from terminus.config.settings import get_settings
from terminus.observability.metrics import record_auth_event

_log = structlog.get_logger("terminus.auth")
_UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


def _bearer_token(request: Request) -> str | None:
    """Return the Bearer token value, or None if no Bearer header is present."""
    header = request.headers.get("Authorization")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


async def authenticate(request: Request) -> str | None:
    """Resolve the trusted agent identity from a Bearer JWT.

    Sets request.state.trusted_agent_id to the verified sub, or to None on the
    permissive legacy path. Raises HTTPException(401) for an invalid token, an
    unknown/disabled sub, or a missing token when require_auth is enabled.
    """
    settings = get_settings()
    token = _bearer_token(request)

    if token is not None:
        result = verify_token(
            token,
            settings.jwt_secret,
            get_registry(),
            require_exp=bool(settings.jwt_require_exp),
            max_lifetime_seconds=settings.jwt_max_lifetime_seconds,
        )
        if not result.ok:
            record_auth_event("rejected")
            _log.warning("auth_rejected", reason=result.reason)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or unauthorized token.",
                headers=_UNAUTHORIZED_HEADERS,
            )
        record_auth_event("verified")
        request.state.trusted_agent_id = result.agent_id
        return result.agent_id

    # No Bearer token present.
    if settings.require_auth:
        record_auth_event("rejected")
        _log.warning("auth_rejected", reason="missing_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers=_UNAUTHORIZED_HEADERS,
        )
    record_auth_event("legacy")
    _log.warning("auth_legacy_unauthenticated")
    request.state.trusted_agent_id = None
    return None
