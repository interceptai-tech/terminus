"""JWT expiry enforcement and minted-lifetime cap (GAPS M1, spec section 5).

Taxonomy is deliberately flat: every expiry/lifetime/claim failure is
invalid_token (no probing signal); registry failures stay unknown_agent.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt as pyjwt

from terminus.auth.registry import AgentEntry, AgentRegistry
from terminus.auth.tokens import mint_token, verify_token

_SECRET = "unit-test-jwt-secret-that-is-at-least-32-bytes-long"
_REG = AgentRegistry(agents=[AgentEntry(id="agent_x", status="active")])


def _raw(claims: dict[str, object]) -> str:
    return pyjwt.encode(claims, _SECRET, algorithm="HS256")


def _now() -> int:
    return int(datetime.now(UTC).timestamp())


def test_expired_token_rejected_regardless_of_require_exp() -> None:
    token = mint_token("agent_x", _SECRET, expires_in=timedelta(seconds=-60))
    assert verify_token(token, _SECRET, _REG).ok is False
    assert verify_token(token, _SECRET, _REG, require_exp=True).ok is False


def test_no_exp_accepted_when_not_required() -> None:
    token = mint_token("agent_x", _SECRET, expires_in=None)
    assert verify_token(token, _SECRET, _REG, require_exp=False).ok is True


def test_no_exp_rejected_when_required() -> None:
    token = mint_token("agent_x", _SECRET, expires_in=None)
    result = verify_token(token, _SECRET, _REG, require_exp=True)
    assert result.ok is False
    assert result.reason == "invalid_token"


def test_lifetime_over_cap_rejected() -> None:
    token = mint_token("agent_x", _SECRET, expires_in=timedelta(days=365))
    result = verify_token(token, _SECRET, _REG, max_lifetime_seconds=86_400)
    assert result.ok is False
    assert result.reason == "invalid_token"


def test_lifetime_within_cap_accepted() -> None:
    token = mint_token("agent_x", _SECRET, expires_in=timedelta(hours=1))
    assert verify_token(token, _SECRET, _REG, max_lifetime_seconds=86_400).ok is True


def test_cap_requires_iat() -> None:
    token = _raw({"sub": "agent_x", "exp": _now() + 3600})  # no iat
    result = verify_token(token, _SECRET, _REG, max_lifetime_seconds=86_400)
    assert result.ok is False
    assert result.reason == "invalid_token"


def test_cap_requires_exp_even_without_require_exp() -> None:
    token = mint_token("agent_x", _SECRET, expires_in=None)  # iat only
    result = verify_token(token, _SECRET, _REG, require_exp=False, max_lifetime_seconds=86_400)
    assert result.ok is False


def test_exp_not_after_iat_rejected() -> None:
    now = _now()
    token = _raw({"sub": "agent_x", "iat": now, "exp": now})
    assert verify_token(token, _SECRET, _REG, max_lifetime_seconds=86_400).ok is False


def test_non_integer_claims_rejected_under_cap() -> None:
    now = _now()
    token = _raw({"sub": "agent_x", "iat": str(now), "exp": now + 60})
    assert verify_token(token, _SECRET, _REG, max_lifetime_seconds=86_400).ok is False


def test_unknown_sub_stays_unknown_agent_under_hardening() -> None:
    token = mint_token("ghost", _SECRET, expires_in=timedelta(hours=1))
    result = verify_token(token, _SECRET, _REG, require_exp=True, max_lifetime_seconds=86_400)
    assert result.ok is False
    assert result.reason == "unknown_agent"


def test_wrong_algorithm_still_rejected() -> None:
    token = pyjwt.encode({"sub": "agent_x", "exp": _now() + 60}, _SECRET, algorithm="HS512")
    assert verify_token(token, _SECRET, _REG, require_exp=True).ok is False


def test_cli_default_token_verifies_under_hardened_posture() -> None:
    token = mint_token("agent_x", _SECRET, expires_in=timedelta(days=30))
    result = verify_token(token, _SECRET, _REG, require_exp=True, max_lifetime_seconds=31 * 86_400)
    assert result.ok is True


def test_string_exp_rejected_under_require_exp_no_cap() -> None:
    # GAPS L10: exp as a numeric string must be rejected when require_exp is on,
    # even without a lifetime cap. PyJWT would otherwise coerce it via int().
    token = _raw({"sub": "agent_x", "exp": str(_now() + 3600)})
    result = verify_token(token, _SECRET, _REG, require_exp=True)
    assert result.ok is False
    assert result.reason == "invalid_token"


def test_bool_exp_rejected_under_require_exp_no_cap() -> None:
    # Note: this token is currently rejected by PyJWT's own expiry check first
    # (int(True) == 1, i.e. 1970, so it reads as expired), not by the require_exp
    # shape guard. The string-exp test above is what pins the hoisted guard's new
    # code path; keep this as a defense-in-depth invariant (bool exp must fail).
    token = _raw({"sub": "agent_x", "exp": True})
    assert verify_token(token, _SECRET, _REG, require_exp=True).ok is False


def test_string_exp_still_accepted_on_legacy_no_require_path() -> None:
    # Unchanged behavior: with require_exp False and no cap, no shape check runs.
    token = _raw({"sub": "agent_x", "exp": str(_now() + 3600)})
    assert verify_token(token, _SECRET, _REG).ok is True
