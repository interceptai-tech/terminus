"""Schema-version matrix: v1 lines verify forever; v2 adds signed MCP context.

The frozen _V1_EVENT below is a pre-v2 audit event exactly as the shipped signer
produced it before schema_version existed (the original 18 signed fields, nothing
else). Signing it here with the same _sign_event over the frozen v1 field set is
cryptographically identical to a line captured from a pre-upgrade deployment.
"""

from __future__ import annotations

import json

from terminus.audit.audit_logger import (
    AUDIT_SCHEMA_VERSION,
    AUDIT_SIGNED_FIELDS,
    GENESIS_SIGNATURE,
    _sign_event,
)
from terminus.audit.verify import _SIGNED_FIELDS_V1, verify_audit_chain

_KEY = "k" * 40

_V1_EVENT: dict = {
    "event_time": "2026-07-06T12:00:00+00:00",
    "request_id": "legacy-1",
    "agent_id": "analytics_agent_42",
    "agent_authenticated": True,
    "decision": "deny",
    "reason": "Destructive operation is not allowed",
    "reason_code": "policy_rule",
    "policy_id": "block_all_destructive_operations",
    "operation": "DROP",
    "tables": ["public.users"],
    "risk_score": 1.0,
    "risk_reasons": ["Destructive operation: DROP"],
    "remediation_present": True,
    "rewrite_suggested": False,
    "sql_sha256": "ab" * 32,
    "security_flags": {},
    "metadata_keys": [],
    "sequence": 0,
}


def _line(event: dict, fields: tuple[str, ...], prev: str) -> tuple[str, str]:
    """Render one signed log line the way the signer would; return (line, signature)."""
    sig = _sign_event({k: event[k] for k in fields}, prev, _KEY)
    full = {
        **event,
        "event": "terminus_intercept_decision",
        "event_signature": sig,
        "previous_signature": prev,
    }
    return json.dumps(full), sig


def _v2_event(
    sequence: int,
    *,
    tool: str = "execute",
    status: str | None = "approved",
    enforcement_mode: str = "enforce",
    would_deny: bool = False,
    would_deny_reason_code: str | None = None,
    operator_id: str | None = None,
    approval_source: str | None = None,
) -> dict:
    return {
        **_V1_EVENT,
        "request_id": f"mcp-{sequence}",
        "sequence": sequence,
        "schema_version": AUDIT_SCHEMA_VERSION,
        "mcp_tool": tool,
        "mcp_approval_status": status,
        "enforcement_mode": enforcement_mode,
        "would_deny": would_deny,
        "would_deny_reason_code": would_deny_reason_code,
        # v4 fields (see _v4_event below); stamped here too because this
        # helper signs over the LIVE AUDIT_SIGNED_FIELDS tuple, which now
        # includes them -- omitting them would KeyError in _line().
        "operator_id": operator_id,
        "approval_source": approval_source,
    }


def test_v1_field_set_is_the_frozen_18() -> None:
    from terminus.audit.verify import _SIGNED_FIELDS_V2, _SIGNED_FIELDS_V3

    # The verifier's copy of history's contract: exactly the pre-v2 fields, and the
    # v2 tuple is exactly v1 plus the three v2 additions, v3 is v2 plus three more,
    # and the live set is v3 plus the two v4 operator-identity additions.
    assert set(_SIGNED_FIELDS_V1) == set(_V1_EVENT.keys())
    assert set(_SIGNED_FIELDS_V2) == set(_SIGNED_FIELDS_V1) | {
        "schema_version",
        "mcp_tool",
        "mcp_approval_status",
    }
    assert set(_SIGNED_FIELDS_V3) == set(_SIGNED_FIELDS_V2) | {
        "enforcement_mode",
        "would_deny",
        "would_deny_reason_code",
    }
    assert set(AUDIT_SIGNED_FIELDS) == set(_SIGNED_FIELDS_V3) | {
        "operator_id",
        "approval_source",
    }


def test_v1_line_still_verifies() -> None:
    line, _ = _line(_V1_EVENT, _SIGNED_FIELDS_V1, GENESIS_SIGNATURE)
    result = verify_audit_chain([line], _KEY, require_genesis=True)
    assert result.ok, result.failures


def test_v2_round_trip_signs_mcp_values() -> None:
    line, _ = _line(_v2_event(0), AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    result = verify_audit_chain([line], _KEY, require_genesis=True)
    assert result.ok, result.failures
    rendered = json.loads(line)
    assert rendered["mcp_tool"] == "execute"
    assert rendered["mcp_approval_status"] == "approved"
    assert rendered["schema_version"] == AUDIT_SCHEMA_VERSION


def test_mixed_v1_then_v2_chain_verifies() -> None:
    # Exactly what an in-place upgrade produces: v1 lines then v2 lines, one chain.
    line1, sig1 = _line(_V1_EVENT, _SIGNED_FIELDS_V1, GENESIS_SIGNATURE)
    line2, _ = _line(_v2_event(1), AUDIT_SIGNED_FIELDS, sig1)
    result = verify_audit_chain([line1, line2], _KEY, require_genesis=True)
    assert result.ok, result.failures
    assert result.verified_count == 2


def test_tampered_mcp_value_is_detected() -> None:
    # Intentionally tracks the CURRENT schema version (_v2_event stamps the live
    # constant); the frozen-v2 twin is test_tampered_frozen_v2_value_is_detected.
    line, _ = _line(_v2_event(0), AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    doctored = json.loads(line)
    doctored["mcp_approval_status"] = "denied"  # flip the recorded outcome
    result = verify_audit_chain([json.dumps(doctored)], _KEY, require_genesis=True)
    assert not result.ok
    assert result.failures[0].reason == "signature_mismatch"


def test_downgrade_strip_is_detected() -> None:
    # Stripping the versioned fields makes the line select as v1, but the stored
    # signature was computed over the full payload, so the recomputation mismatches.
    # Intentionally tracks the CURRENT schema version (_v2_event stamps the live
    # constant); the frozen-v2 twin is test_downgrade_strip_frozen_v2_is_detected.
    line, _ = _line(_v2_event(0), AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    doctored = json.loads(line)
    for field in ("schema_version", "mcp_tool", "mcp_approval_status"):
        del doctored[field]
    result = verify_audit_chain([json.dumps(doctored)], _KEY, require_genesis=True)
    assert not result.ok
    assert result.failures[0].reason == "signature_mismatch"


def test_unknown_schema_version_fails_closed() -> None:
    # AUDIT_SCHEMA_VERSION + 1 is unknown by construction, whatever the live
    # version currently is -- unlike a hardcoded literal, this stays true
    # across future schema bumps instead of silently becoming a "known" version.
    event = {**_v2_event(0), "schema_version": AUDIT_SCHEMA_VERSION + 1}
    line, _ = _line(event, AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    result = verify_audit_chain([line], _KEY, require_genesis=True)
    assert not result.ok
    assert any(f.reason == "unknown_schema_version" for f in result.failures)


def test_build_event_defaults_mcp_fields_to_none() -> None:
    # The HTTP /intercept path passes no MCP kwargs; every event is still v2 with
    # both MCP fields None, keeping the drift test a simple key-set equality.
    from terminus.audit.audit_logger import AuditLogger
    from terminus.config.settings import get_settings
    from terminus.parser.sql_parser import parse_sql
    from terminus.policy.policy_engine import PolicyEngine

    parsed = parse_sql("DROP TABLE public.users")
    decision = PolicyEngine.from_default_policy().evaluate(parsed, agent_id="a1")
    event = AuditLogger._build_event(
        request_id="r1",
        agent_id="a1",
        parsed_sql=parsed,
        decision=decision,
        remediation_present=True,
        metadata={},
        sql="DROP TABLE public.users",
        key=get_settings().audit_hmac_key,
    )
    assert event["schema_version"] == AUDIT_SCHEMA_VERSION
    assert event["mcp_tool"] is None
    assert event["mcp_approval_status"] is None


def _v2_event_frozen(sequence: int) -> dict:
    """A pre-v3 event exactly as the v2 signer produced it (21 fields)."""
    return {
        **_V1_EVENT,
        "request_id": f"v2-{sequence}",
        "sequence": sequence,
        "schema_version": 2,
        "mcp_tool": "query",
        "mcp_approval_status": None,
    }


def _v3_event(sequence: int, *, would_deny: bool = True) -> dict:
    return {
        **_v2_event_frozen(sequence),
        "request_id": f"v3-{sequence}",
        "schema_version": AUDIT_SCHEMA_VERSION,
        "enforcement_mode": "observe" if would_deny else "enforce",
        "would_deny": would_deny,
        "would_deny_reason_code": "schema_whitelist" if would_deny else None,
        # v4 fields; see the note on _v2_event -- this helper also signs over
        # the live AUDIT_SIGNED_FIELDS tuple.
        "operator_id": None,
        "approval_source": None,
    }


def test_v3_field_set_is_v2_plus_three() -> None:
    from terminus.audit.verify import _SIGNED_FIELDS_V2, _SIGNED_FIELDS_V3

    assert set(_SIGNED_FIELDS_V2) == set(_SIGNED_FIELDS_V1) | {
        "schema_version",
        "mcp_tool",
        "mcp_approval_status",
    }
    assert set(_SIGNED_FIELDS_V3) == set(_SIGNED_FIELDS_V2) | {
        "enforcement_mode",
        "would_deny",
        "would_deny_reason_code",
    }


def test_v2_line_still_verifies() -> None:
    from terminus.audit.verify import _SIGNED_FIELDS_V2

    line, _ = _line(_v2_event_frozen(0), _SIGNED_FIELDS_V2, GENESIS_SIGNATURE)
    result = verify_audit_chain([line], _KEY, require_genesis=True)
    assert result.ok, result.failures


def test_mixed_v1_v2_v3_chain_verifies() -> None:
    from terminus.audit.verify import _SIGNED_FIELDS_V2

    l1, s1 = _line(_V1_EVENT, _SIGNED_FIELDS_V1, GENESIS_SIGNATURE)
    l2, s2 = _line({**_v2_event_frozen(1)}, _SIGNED_FIELDS_V2, s1)
    l3, _ = _line(_v3_event(2), AUDIT_SIGNED_FIELDS, s2)
    result = verify_audit_chain([l1, l2, l3], _KEY, require_genesis=True)
    assert result.ok, result.failures
    assert result.verified_count == 3


def test_tampered_would_deny_detected() -> None:
    line, _ = _line(_v3_event(0), AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    doctored = json.loads(line)
    doctored["would_deny"] = False  # hide the observe evidence
    result = verify_audit_chain([json.dumps(doctored)], _KEY, require_genesis=True)
    assert not result.ok
    assert result.failures[0].reason == "signature_mismatch"


def test_unknown_v4_fails_closed() -> None:
    # AUDIT_SCHEMA_VERSION + 1 is unknown by construction (see the note on
    # test_unknown_schema_version_fails_closed above).
    event = {**_v3_event(0), "schema_version": AUDIT_SCHEMA_VERSION + 1}
    line, _ = _line(event, AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    result = verify_audit_chain([line], _KEY, require_genesis=True)
    assert not result.ok
    assert any(f.reason == "unknown_schema_version" for f in result.failures)


def test_tampered_frozen_v2_value_is_detected() -> None:
    # A GENUINE v2 line (literal schema_version 2, signed over the frozen 21-field
    # tuple): tampering with a signed MCP value must still break its signature after
    # the v3 bump, proving the frozen _SIGNED_FIELDS_V2 path is adversarially sound.
    from terminus.audit.verify import _SIGNED_FIELDS_V2

    line, _ = _line(_v2_event_frozen(0), _SIGNED_FIELDS_V2, GENESIS_SIGNATURE)
    doctored = json.loads(line)
    doctored["mcp_approval_status"] = "approved"  # forge an approval onto the record
    result = verify_audit_chain([json.dumps(doctored)], _KEY, require_genesis=True)
    assert not result.ok
    assert result.failures[0].reason == "signature_mismatch"


def test_downgrade_strip_frozen_v2_is_detected() -> None:
    # Stripping the v2 fields from a GENUINE v2 line makes it select as v1, but the
    # stored signature was computed over the frozen v2 payload, so it mismatches.
    from terminus.audit.verify import _SIGNED_FIELDS_V2

    line, _ = _line(_v2_event_frozen(0), _SIGNED_FIELDS_V2, GENESIS_SIGNATURE)
    doctored = json.loads(line)
    for field in ("schema_version", "mcp_tool", "mcp_approval_status"):
        del doctored[field]
    result = verify_audit_chain([json.dumps(doctored)], _KEY, require_genesis=True)
    assert not result.ok
    assert result.failures[0].reason == "signature_mismatch"


# --- v4 adds operator_id + approval_source (Task 1: operator identity through
# the broker). Same frozen-snapshot pattern as v2/v3 above: _SIGNED_FIELDS_V3
# is v3's field set copied verbatim into verify.py so pre-v4 logs keep
# verifying, and the live AUDIT_SIGNED_FIELDS tuple gains the two new fields.


def _v3_event_frozen(sequence: int) -> dict:
    """A pre-v4 event exactly as the v3 signer produced it (24 fields)."""
    return {
        **_v2_event_frozen(sequence),
        "request_id": f"v3f-{sequence}",
        "schema_version": 3,
        "enforcement_mode": "enforce",
        "would_deny": False,
        "would_deny_reason_code": None,
    }


def _v4_event(
    sequence: int,
    *,
    operator_id: str | None = "alice",
    approval_source: str | None = "plane",
) -> dict:
    return {
        **_v3_event_frozen(sequence),
        "request_id": f"v4-{sequence}",
        "schema_version": AUDIT_SCHEMA_VERSION,
        "operator_id": operator_id,
        "approval_source": approval_source,
    }


def test_v4_field_set_is_v3_plus_two() -> None:
    from terminus.audit.audit_logger import AUDIT_SIGNED_FIELDS
    from terminus.audit.verify import _SIGNED_FIELDS_V3

    assert set(AUDIT_SIGNED_FIELDS) == set(_SIGNED_FIELDS_V3) | {"operator_id", "approval_source"}


def test_v3_snapshot_is_frozen_24() -> None:
    from terminus.audit.verify import _SIGNED_FIELDS_V3

    assert len(_SIGNED_FIELDS_V3) == 24
    assert "operator_id" not in _SIGNED_FIELDS_V3


def test_v3_frozen_line_still_verifies() -> None:
    from terminus.audit.verify import _SIGNED_FIELDS_V3

    line, _ = _line(_v3_event_frozen(0), _SIGNED_FIELDS_V3, GENESIS_SIGNATURE)
    result = verify_audit_chain([line], _KEY, require_genesis=True)
    assert result.ok, result.failures


def test_v4_round_trip_signs_operator_values() -> None:
    line, _ = _line(_v4_event(0), AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    result = verify_audit_chain([line], _KEY, require_genesis=True)
    assert result.ok, result.failures
    rendered = json.loads(line)
    assert rendered["operator_id"] == "alice"
    assert rendered["approval_source"] == "plane"
    assert rendered["schema_version"] == AUDIT_SCHEMA_VERSION


def test_mixed_v1_v2_v3_v4_chain_verifies() -> None:
    # Exactly what an in-place upgrade across all four schema versions produces.
    from terminus.audit.verify import _SIGNED_FIELDS_V2, _SIGNED_FIELDS_V3

    l1, s1 = _line(_V1_EVENT, _SIGNED_FIELDS_V1, GENESIS_SIGNATURE)
    l2, s2 = _line(_v2_event_frozen(1), _SIGNED_FIELDS_V2, s1)
    l3, s3 = _line(_v3_event_frozen(2), _SIGNED_FIELDS_V3, s2)
    l4, _ = _line(_v4_event(3), AUDIT_SIGNED_FIELDS, s3)
    result = verify_audit_chain([l1, l2, l3, l4], _KEY, require_genesis=True)
    assert result.ok, result.failures
    assert result.verified_count == 4


def test_tampered_operator_id_is_detected() -> None:
    line, _ = _line(_v4_event(0), AUDIT_SIGNED_FIELDS, GENESIS_SIGNATURE)
    doctored = json.loads(line)
    doctored["operator_id"] = "mallory"  # forge a different approver onto the record
    result = verify_audit_chain([json.dumps(doctored)], _KEY, require_genesis=True)
    assert not result.ok
    assert result.failures[0].reason == "signature_mismatch"
