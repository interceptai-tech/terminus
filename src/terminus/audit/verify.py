"""Independent verification of the Terminus audit HMAC chain.

Verifies three event kinds sharing ONE chain: terminus_intercept_decision (policy
decisions), terminus_trust_level_change (graduated-autonomy promotions/demotions),
and terminus_reveal_event (plane reveal-round-trip serve/reject outcomes). All
three carry sequence/event_signature/previous_signature against the same running
prev_signature, so interleaving them, deleting any kind, or reordering across
kinds all trip the same linkage/sequence checks below.

Reconstructs each signed payload by SELECTING the signed field set for that line's
event name and schema_version (decision lines: no schema_version uses the frozen v1
set, schema_version 2 uses the frozen v2 set, schema_version 3 uses the frozen v3
set, the current AUDIT_SCHEMA_VERSION uses the live AUDIT_SIGNED_FIELDS;
trust-change lines: schema_version 1 uses TRUST_CHANGE_SIGNED_FIELDS; reveal-event
lines: schema_version 1 uses REVEAL_SIGNED_FIELDS; any other value, for any kind,
fails closed with unknown_schema_version), recomputes the signature with the real
signer, and checks the previous_signature linkage. O(n) and streamable: holds only
the running prev_signature plus collected failures, so memory is bounded by the
failure count, not the log size. Verify large histories in start_signature-anchored
chunks.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from pydantic import BaseModel

from terminus.audit.audit_logger import (
    AUDIT_SCHEMA_VERSION,
    AUDIT_SIGNED_FIELDS,
    GENESIS_SIGNATURE,
    REVEAL_EVENT_NAME,
    REVEAL_SIGNED_FIELDS,
    TRUST_CHANGE_SIGNED_FIELDS,
    _sign_event,
)

_AUDIT_EVENT_NAME = "terminus_intercept_decision"
_TRUST_EVENT_NAME = "terminus_trust_level_change"
_REVEAL_EVENT_NAME = REVEAL_EVENT_NAME
_SNIPPET_MAX = 120

# Frozen copy of the v1 signed field set (pre-schema_version history). Copied
# verbatim rather than derived from AUDIT_SIGNED_FIELDS so future signer edits can
# never silently rewrite the contract that historical lines were signed under.
_SIGNED_FIELDS_V1: tuple[str, ...] = (
    "event_time",
    "request_id",
    "agent_id",
    "agent_authenticated",
    "decision",
    "reason",
    "reason_code",
    "policy_id",
    "operation",
    "tables",
    "risk_score",
    "risk_reasons",
    "remediation_present",
    "rewrite_suggested",
    "sql_sha256",
    "security_flags",
    "metadata_keys",
    "sequence",
)

# Frozen copy of the v2 signed field set (schema v2 with MCP enforcement context).
# Added schema_version, mcp_tool, mcp_approval_status. v3 extends this with
# enforcement_mode, would_deny, would_deny_reason_code (graduated-autonomy evidence).
# Copied verbatim so v3+ signer changes never silently rewrite v2's contract.
_SIGNED_FIELDS_V2: tuple[str, ...] = (
    "event_time",
    "request_id",
    "agent_id",
    "agent_authenticated",
    "decision",
    "reason",
    "reason_code",
    "policy_id",
    "operation",
    "tables",
    "risk_score",
    "risk_reasons",
    "remediation_present",
    "rewrite_suggested",
    "sql_sha256",
    "security_flags",
    "metadata_keys",
    "sequence",
    "schema_version",
    "mcp_tool",
    "mcp_approval_status",
)

# Frozen copy of the v3 signed field set (schema v3 with graduated-autonomy
# evidence). Added enforcement_mode, would_deny, would_deny_reason_code on top
# of v2. v4 extends this with operator_id, approval_source (who approved a
# hold and via which channel). Copied verbatim so v4+ signer changes never
# silently rewrite v3's contract.
_SIGNED_FIELDS_V3: tuple[str, ...] = (
    "event_time",
    "request_id",
    "agent_id",
    "agent_authenticated",
    "decision",
    "reason",
    "reason_code",
    "policy_id",
    "operation",
    "tables",
    "risk_score",
    "risk_reasons",
    "remediation_present",
    "rewrite_suggested",
    "sql_sha256",
    "security_flags",
    "metadata_keys",
    "sequence",
    "schema_version",
    "mcp_tool",
    "mcp_approval_status",
    "enforcement_mode",
    "would_deny",
    "would_deny_reason_code",
)


def _fields_for_version(version: object) -> tuple[str, ...] | None:
    """Signed field set for a decision line's schema_version; None = unknown (fail closed)."""
    if version is None:
        return _SIGNED_FIELDS_V1
    if version == 2:
        return _SIGNED_FIELDS_V2
    if version == 3:
        return _SIGNED_FIELDS_V3
    if version == AUDIT_SCHEMA_VERSION:
        return AUDIT_SIGNED_FIELDS
    return None


def _select_fields(event_name: str, version: object) -> tuple[str, ...] | None:
    """Signed field set for a line, dispatched by event kind then schema_version.

    None means unknown version for that kind: the caller routes this to the same
    unknown_schema_version failure path used for decision lines, so an unrecognized
    trust-change or reveal-event schema_version fails closed exactly like an
    unrecognized decision one.
    """
    if event_name == _AUDIT_EVENT_NAME:
        return _fields_for_version(version)
    if event_name == _TRUST_EVENT_NAME:
        return TRUST_CHANGE_SIGNED_FIELDS if version == 1 else None
    if event_name == _REVEAL_EVENT_NAME:
        return REVEAL_SIGNED_FIELDS if version == 1 else None
    return None  # unreachable: caller filters names first


class AuditChainVerificationError(Exception):
    """Raised on structurally invalid input: a line that is not JSON, or a
    terminus_intercept_decision / terminus_trust_level_change line missing a signed
    field or a signature.

    Carries the offending line's index and a short snippet for diagnostics.
    """

    def __init__(
        self,
        message: str,
        *,
        line_index: int | None = None,
        snippet: str | None = None,
    ) -> None:
        self.line_index = line_index
        self.snippet = snippet[:_SNIPPET_MAX] if snippet else None
        detail = message if line_index is None else f"{message} (line {line_index})"
        super().__init__(detail)


class AuditChainFailure(BaseModel):
    """One failed check, by position in the verified sequence."""

    index: int
    request_id: str | None
    # signature_mismatch|broken_link|anchor_mismatch|sequence_gap|tail_truncation|
    # unknown_schema_version
    reason: str
    expected: str
    actual: str


class AuditChainResult(BaseModel):
    """Outcome of verifying a sequence of audit events."""

    ok: bool
    verified_count: int
    failures: list[AuditChainFailure]


def _resolve_anchor(require_genesis: bool, start_signature: str | None) -> str | None:
    if require_genesis:
        if start_signature is not None and start_signature != GENESIS_SIGNATURE:
            raise ValueError("require_genesis conflicts with a non-genesis start_signature")
        return GENESIS_SIGNATURE
    return start_signature


def verify_audit_chain(
    log_lines: Iterable[str],
    hmac_key: str,
    *,
    require_genesis: bool = False,
    start_signature: str | None = None,
    expected_head_signature: str | None = None,
    expected_head_sequence: int | None = None,
) -> AuditChainResult:
    """Verify the HMAC chain of audit events parsed from structured log lines.

    require_genesis=True is sugar for start_signature=GENESIS_SIGNATURE. With no
    anchor, the first event's own previous_signature is taken as the start, so a
    recent window verifies internally without replaying from genesis.

    ``start_signature`` is the older FROM anchor (the predecessor of the first
    verified event; not itself in ``log_lines``). ``expected_head_signature`` /
    ``expected_head_sequence`` are the newer TO anchor: the latest out-of-band
    captured head, which MUST fall within ``log_lines`` so its presence can be
    proven. They must be supplied together (an incomplete anchor raises), so the
    substituted-segment check never silently degrades to a length-only bound. When
    verifying a long history in start_signature-anchored chunks, pass the head only
    on the chunk that actually contains it (normally the last).
    """
    if (expected_head_signature is None) != (expected_head_sequence is None):
        raise ValueError(
            "expected_head_signature and expected_head_sequence must be provided together"
        )
    anchor = _resolve_anchor(require_genesis, start_signature)

    failures: list[AuditChainFailure] = []
    verified = 0
    seq = 0
    prev_sig: str | None = None
    prev_event_seq: int | None = None
    last_event_seq: int | None = None
    # Signature of the event observed AT expected_head_sequence, if any. The captured
    # head must actually appear in the verified chain, not merely be a lower bound.
    head_seq_signature: str | None = None

    for raw_index, raw in enumerate(log_lines):
        line = raw.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditChainVerificationError(
                "log line is not valid JSON", line_index=raw_index, snippet=line
            ) from exc
        event_name = event.get("event") if isinstance(event, dict) else None
        if event_name not in (_AUDIT_EVENT_NAME, _TRUST_EVENT_NAME, _REVEAL_EVENT_NAME):
            continue  # not a decision/trust-change/reveal line (e.g. checkpoint, foreign)

        version = event.get("schema_version")
        fields = _select_fields(event_name, version)
        try:
            stored_sig = event["event_signature"]
            stored_prev = event["previous_signature"]
            selected = None if fields is None else {key: event[key] for key in fields}
        except KeyError as exc:
            raise AuditChainVerificationError(
                f"audit event missing required field {exc.args[0]!r}",
                line_index=raw_index,
                snippet=line,
            ) from exc

        request_id = event.get("request_id")

        # (1) Signature integrity: recompute over the event's own stated prev, using
        # the field set its schema_version declares. An unknown version cannot be
        # recomputed at all: fail closed on this line, keep verifying the rest.
        if selected is None:
            sig_ok = False
            failures.append(
                AuditChainFailure(
                    index=seq,
                    request_id=request_id,
                    reason="unknown_schema_version",
                    expected=(
                        f"absent (v1) or {AUDIT_SCHEMA_VERSION}"
                        if event_name == _AUDIT_EVENT_NAME
                        else "1"
                    ),
                    actual=str(version),
                )
            )
        else:
            recomputed = _sign_event(selected, stored_prev, hmac_key)
            sig_ok = recomputed == stored_sig
            if not sig_ok:
                failures.append(
                    AuditChainFailure(
                        index=seq,
                        request_id=request_id,
                        reason="signature_mismatch",
                        expected=stored_sig,
                        actual=recomputed,
                    )
                )

        # (2) Linkage: stored_prev must match the anchor (first) or prior signature.
        if seq == 0:
            expected_prev = stored_prev if anchor is None else anchor
        else:
            assert prev_sig is not None  # always set after the first event
            expected_prev = prev_sig
        link_ok = stored_prev == expected_prev
        if not link_ok:
            failures.append(
                AuditChainFailure(
                    index=seq,
                    request_id=request_id,
                    reason="anchor_mismatch" if seq == 0 else "broken_link",
                    expected=expected_prev,
                    actual=stored_prev,
                )
            )

        # (3) Sequence continuity: the signed per-event sequence must be 0 at a
        # genesis anchor and increment by 1 thereafter. A gap flags a deletion or
        # reorder even where linkage alone might not, and the last observed sequence
        # is the head used for tail-truncation detection below.
        event_seq = event.get("sequence") if selected is None else selected["sequence"]
        if seq == 0:
            expected_seq = 0 if anchor == GENESIS_SIGNATURE else event_seq
        elif isinstance(prev_event_seq, int):
            expected_seq = prev_event_seq + 1
        else:
            expected_seq = event_seq
        seq_ok = event_seq == expected_seq
        if not seq_ok:
            failures.append(
                AuditChainFailure(
                    index=seq,
                    request_id=request_id,
                    reason="sequence_gap",
                    expected=str(expected_seq),
                    actual=str(event_seq),
                )
            )

        if sig_ok and link_ok and seq_ok:
            verified += 1
        prev_sig = stored_sig
        if isinstance(event_seq, int):
            prev_event_seq = event_seq
            last_event_seq = event_seq
            if event_seq == expected_head_sequence:
                head_seq_signature = stored_sig
        seq += 1

    # (4) Tail truncation: the out-of-band captured head must ACTUALLY APPEAR in the
    # verified chain. Reaching a higher sequence is not enough: because the chain
    # re-roots at genesis every process restart, the same key signs many valid
    # segments, so a longer but divergent segment could otherwise be substituted for
    # the anchored one. So when the captured sequence is provided, require an event
    # at exactly that sequence whose signature equals the captured head signature.
    # Both anchors are present or both absent (enforced at entry), so testing the
    # sequence alone is enough to know the head signature is also set.
    if expected_head_sequence is not None:
        if last_event_seq is None or last_event_seq < expected_head_sequence:
            # The chain never reached the captured head: events were dropped.
            failures.append(
                AuditChainFailure(
                    index=seq,
                    request_id=None,
                    reason="tail_truncation",
                    expected=str(expected_head_sequence),
                    actual=str(last_event_seq),
                )
            )
        elif head_seq_signature != expected_head_signature:
            # The captured sequence is present (or exceeded) but the signature there
            # is not the captured head: a divergent or substituted chain, or a head
            # that was never inside the verified window.
            failures.append(
                AuditChainFailure(
                    index=seq,
                    request_id=None,
                    reason="tail_truncation",
                    expected=expected_head_signature or "",
                    actual=head_seq_signature or "",
                )
            )

    return AuditChainResult(ok=not failures, verified_count=verified, failures=failures)
