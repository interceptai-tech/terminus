"""JWT verification and minting for agent identity (HS256)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
from pydantic import BaseModel

from terminus.auth.registry import AgentRegistry

_ALGORITHM = "HS256"


class AuthResult(BaseModel):
    """Outcome of verifying a token."""

    ok: bool
    agent_id: str | None = None
    reason: str | None = None  # "invalid_token" | "unknown_agent"


def verify_token(
    token: str,
    secret: str,
    registry: AgentRegistry,
    *,
    require_exp: bool = False,
    max_lifetime_seconds: int = 0,
) -> AuthResult:
    """Verify an HS256 JWT and check its sub against the registry.

    Algorithm is pinned to HS256 (rejects alg=none and algorithm confusion).
    PyJWT verifies a present `exp` with zero leeway; require_exp additionally
    makes the claim mandatory. max_lifetime_seconds > 0 caps the MINTED
    lifetime (exp - iat) and makes both claims mandatory ints: a bearer
    credential minted for years is rejected even though it has an expiry.
    Missing iat fails closed. Any signature/expiry/format/lifetime failure ->
    invalid_token (one bucket: no probing signal). A valid token whose sub is
    not a registered, active agent -> unknown_agent.
    """
    require = ["sub"]
    if require_exp:
        require.append("exp")
    if max_lifetime_seconds > 0:
        require.extend(claim for claim in ("exp", "iat") if claim not in require)
    try:
        payload = jwt.decode(token, secret, algorithms=[_ALGORITHM], options={"require": require})
    except jwt.InvalidTokenError:
        return AuthResult(ok=False, reason="invalid_token")

    if require_exp:
        exp = payload.get("exp")
        # bool is an int subclass; exclude it so exp=true cannot slip through, and
        # reject a numeric-string exp that PyJWT would coerce (GAPS L10). exp is a
        # required claim here (in the `require` list), so it is present.
        if not isinstance(exp, int) or isinstance(exp, bool):
            return AuthResult(ok=False, reason="invalid_token")

    if max_lifetime_seconds > 0:
        exp = payload.get("exp")
        iat = payload.get("iat")
        # bool is an int subclass; exclude it so exp=true cannot slip through.
        if (
            not isinstance(exp, int)
            or isinstance(exp, bool)
            or not isinstance(iat, int)
            or isinstance(iat, bool)
            or exp <= iat
            or exp - iat > max_lifetime_seconds
        ):
            return AuthResult(ok=False, reason="invalid_token")

    sub = payload.get("sub")
    if not isinstance(sub, str) or not registry.is_active(sub):
        return AuthResult(ok=False, reason="unknown_agent")
    return AuthResult(ok=True, agent_id=sub)


def mint_token(agent_id: str, secret: str, *, expires_in: timedelta | None = None) -> str:
    """Mint an HS256 JWT for an agent. Operator/CLI use only, never at runtime."""
    now = datetime.now(UTC)
    payload: dict[str, object] = {"sub": agent_id, "iat": int(now.timestamp())}
    if expires_in is not None:
        payload["exp"] = int((now + expires_in).timestamp())
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)
