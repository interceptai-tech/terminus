"""Structured, tamper-proof audit logging for Terminus."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
from datetime import UTC, datetime
from typing import Any, TextIO

import structlog
from structlog.contextvars import bound_contextvars, merge_contextvars

from terminus.config.settings import get_settings
from terminus.parser.sql_parser import ParsedSQL
from terminus.policy.policy_engine import PolicyDecision

# A conventional "no previous event" marker for the first link in the chain.
# Not a cryptographic value: it is simply the prev_signature the genesis event
# chains from (64 zeros so it reads as an obvious sentinel in the logs).
GENESIS_SIGNATURE = "0" * 64

# Schema version of the signed event payload. v1 (implicit: no schema_version field)
# is the original 18-field set; v2 adds schema_version plus the MCP enforcement-point
# context; v3 adds graduated-autonomy evidence (enforcement_mode, would_deny,
# would_deny_reason_code). The verifier keeps a frozen copy of each historical field
# set and selects per line, so pre-v3 logs verify forever. Bump this and extend the
# tuple together; verify.py must gain the new version in the same commit (no-drift rule).
AUDIT_SCHEMA_VERSION: int = 3

# The exact fields covered by the HMAC signature. _build_event produces exactly
# these keys; terminus.audit.verify reconstructs the signed payload by SELECTING
# these keys from a log line, ignoring anything structlog adds (timestamp, level,
# event). A test asserts _build_event's keys equal this set so the two never drift.
AUDIT_SIGNED_FIELDS: tuple[str, ...] = (
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

TRUST_CHANGE_EVENT_NAME = "terminus_trust_level_change"
# Signed fields of the trust-change event (its own frozen v1 contract; the event
# carries schema_version for future evolution, same pattern as decision events).
# This is a separate versioning axis from AUDIT_SCHEMA_VERSION: the two event kinds
# share one HMAC chain (same _audit_lock/_last_signature/_sequence) but evolve their
# own field sets independently. verify.py must gain any new version in lockstep.
# Domain separation between the two event kinds does NOT rest on disjoint
# signed field-name sets: they share event_time/agent_id/sequence/schema_version.
# It rests on the FULL signed key sets differing -- each kind has keys the other
# lacks (e.g. AUDIT_SIGNED_FIELDS has "decision", TRUST_CHANGE_SIGNED_FIELDS has
# "new_trust_level") -- so no single JSON object can satisfy both field selections
# at once and be verified as either kind.
TRUST_CHANGE_SIGNED_FIELDS: tuple[str, ...] = (
    "event_time",
    "agent_id",
    "previous_trust_level",
    "new_trust_level",
    "governance_version",
    "trust_changed_by",
    "trust_change_reason",
    "sequence",
    "schema_version",
)

# Default for the two provenance fields when the caller omits them. They are SIGNED
# fields (see TRUST_CHANGE_SIGNED_FIELDS), so they must always be present rather than
# null: a stable literal keeps the signed payload well-formed while still flagging,
# in the audit trail itself, that the human-readable "why" lives outside the log.
_UNSPECIFIED_PROVENANCE = "unspecified: see git history"

# Schema version of the trust-change event payload (independent of AUDIT_SCHEMA_VERSION).
TRUST_CHANGE_SCHEMA_VERSION: int = 1

_last_signature: str = GENESIS_SIGNATURE  # chain head for this process
# Per-segment monotonic event counter. Resets to 0 alongside _last_signature on
# process start, so each process lifetime is one genesis-rooted segment. A signed
# `sequence` on every event lets the verifier prove how many events a segment holds,
# which (checked against an out-of-band captured head) makes tail truncation
# detectable. _audit_lock guards the (_last_signature, _sequence) read-modify-write
# so it stays correct even if audit writing is ever moved off the single event loop.
_sequence: int = 0
_boot_id: str = secrets.token_hex(16)
_audit_lock = threading.Lock()

_CHECKPOINT_EVENT_NAME = "terminus_audit_checkpoint"
_CHECKPOINT_SIGNED_FIELDS: tuple[str, ...] = (
    "boot_id",
    "sequence",
    "head_signature",
    "checkpoint_time",
)


def configure_logging(stream: TextIO | None = None) -> None:
    """Configure structlog using settings from TerminusSettings.

    Binds request_id and agent_id automatically via contextvars for every log entry.
    stream=None keeps the default (stdout). The MCP stdio entrypoint passes
    sys.stderr: stdout there belongs to the MCP protocol framing, and a single log
    line on it would corrupt the transport.
    """
    settings = get_settings()

    log_level = getattr(logging, settings.log_level.upper())

    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        force=True,
    )

    structlog.configure(
        processors=[
            merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(stream),
        cache_logger_on_first_use=True,
    )


def _sign_event(event: dict[str, Any], prev_signature: str, key: str) -> str:
    """Create HMAC signature chaining this event to the previous one."""
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    to_sign = prev_signature.encode("utf-8") + payload
    return hmac.new(key.encode("utf-8"), to_sign, hashlib.sha256).hexdigest()


# Domain-separation tag for the SQL digest. Distinct message space from the event
# and checkpoint HMACs (which sign `prev||payload` and the checkpoint payload) so
# the same key cannot make one an oracle on another. The trailing NUL unambiguously
# separates the tag from the SQL; the v1 versions the scheme so it can evolve.
_SQL_DIGEST_DOMAIN = b"terminus/audit/sql-digest/v1\x00"


def sql_digest(sql: str, key: str) -> str:
    """Return a keyed, one-way digest of the SQL for correlation without leakage.

    A plain sha256(sql) is brute-forceable: SQL is low-entropy and structured, so an
    attacker with the shipped logs can dictionary-attack a PII literal and confirm
    the query. Keying the digest with the secret ``audit_hmac_key`` (via HMAC over a
    domain-separated, versioned message) makes recovery infeasible without the key,
    while staying deterministic within a deployment so a SIEM can still correlate
    repeated queries. Fail closed: an empty key would make HMAC effectively unkeyed
    (it does not raise on its own), so reject it rather than emit a guessable digest.
    """
    if not key:
        raise ValueError("sql_digest requires a non-empty audit key")
    return hmac.new(
        key.encode("utf-8"), _SQL_DIGEST_DOMAIN + sql.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _checkpoint_signature(payload: dict[str, Any], key: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def build_checkpoint(
    *,
    boot_id: str,
    sequence: int,
    head_signature: str,
    key: str,
    checkpoint_time: str | None = None,
) -> dict[str, Any]:
    """Build a signed checkpoint of the current chain head.

    Records (boot_id, sequence, head_signature) and is itself HMAC-signed, so an
    attacker cannot forge one that understates the chain length to mask a tail
    truncation. It is emitted into the log stream so a downstream SIEM captures the
    head out-of-band; verification then feeds that captured (sequence, signature)
    back in as expected_head_* to detect a short tail. The checkpoint only protects
    to the extent it lands somewhere the log-store attacker cannot rewrite.
    """
    when = checkpoint_time if checkpoint_time is not None else datetime.now(UTC).isoformat()
    payload = {
        "boot_id": boot_id,
        "sequence": sequence,
        "head_signature": head_signature,
        "checkpoint_time": when,
    }
    return {
        "event": _CHECKPOINT_EVENT_NAME,
        **payload,
        "checkpoint_signature": _checkpoint_signature(payload, key),
    }


def verify_checkpoint(checkpoint: dict[str, Any], key: str) -> bool:
    """Return True iff the checkpoint's HMAC signature is intact."""
    try:
        payload = {field: checkpoint[field] for field in _CHECKPOINT_SIGNED_FIELDS}
    except KeyError:
        return False
    expected = _checkpoint_signature(payload, key)
    return hmac.compare_digest(expected, str(checkpoint.get("checkpoint_signature", "")))


def emit_shutdown_checkpoint() -> None:
    """Emit a final head checkpoint on graceful shutdown.

    Captures the tail of events written since the last periodic checkpoint, so the
    exposure window does not silently extend across a clean restart. No-op when the
    feature is disabled or nothing has been logged this process lifetime.
    """
    settings = get_settings()
    if (settings.audit_checkpoint_interval or 0) <= 0:
        return
    with _audit_lock:
        if _sequence == 0:
            return  # nothing logged yet; no head to checkpoint
        head_sequence = _sequence - 1
        head_signature = _last_signature
    AuditLogger()._emit_checkpoint(sequence=head_sequence, head_signature=head_signature)


def get_audit_logger() -> AuditLogger:
    """Dependency provider for AuditLogger."""
    return AuditLogger()


class AuditLogger:
    """Tamper-proof audit logger.

    Each log entry is cryptographically signed with HMAC-SHA256.
    The signature includes the previous event's signature, forming a verifiable chain.
    """

    def __init__(self) -> None:
        self._logger = structlog.get_logger("terminus.audit")
        self._settings = get_settings()
        self._key = self._settings.audit_hmac_key

    @staticmethod
    def _build_event(
        *,
        request_id: str,
        agent_id: str | None,
        parsed_sql: ParsedSQL,
        decision: PolicyDecision,
        remediation_present: bool,
        metadata: dict[str, Any] | None,
        sql: str,
        key: str,
        rewrite_suggested: bool = False,
        agent_authenticated: bool = False,
        sequence: int = 0,
        mcp_tool: str | None = None,
        mcp_approval_status: str | None = None,
        enforcement_mode: str = "enforce",
        would_deny: bool = False,
        would_deny_reason_code: str | None = None,
    ) -> dict[str, Any]:
        """Construct the audit event dict before signature fields are added.

        Raw SQL is never included, only a keyed one-way digest (``key`` is the audit
        HMAC key; see ``sql_digest``). ``mcp_tool`` and ``mcp_approval_status`` are
        the schema v2 MCP enforcement-point fields (always present, None on the HTTP
        ``/intercept`` path). ``enforcement_mode``, ``would_deny``, and
        ``would_deny_reason_code`` are schema v3 graduated-autonomy evidence fields:
        always present with "enforce"/False/None defaults when softening was not in play.
        """
        return {
            "event_time": datetime.now(UTC).isoformat(),
            "request_id": request_id,
            "agent_id": agent_id or "unknown",
            "agent_authenticated": agent_authenticated,
            "decision": decision.action,
            "reason": decision.reason,
            "reason_code": decision.reason_code,
            "policy_id": decision.policy_id,
            "operation": parsed_sql.operation,
            "tables": parsed_sql.tables,
            "risk_score": parsed_sql.risk_score,
            "risk_reasons": parsed_sql.risk_reasons,
            "remediation_present": remediation_present,
            "rewrite_suggested": rewrite_suggested,
            # Legacy field name; the value is now a keyed HMAC-SHA256 digest, not a
            # bare sha256 (F8). Still a 64-char hex digest, so consumers are unaffected.
            "sql_sha256": sql_digest(sql, key),
            "security_flags": parsed_sql.security_flags.model_dump(),
            "metadata_keys": sorted((metadata or {}).keys()),
            "sequence": sequence,
            # v2 fields. Always present (None on the HTTP path) so the signed field
            # set is one fixed tuple per version. Values are code constants from the
            # MCP server ("query"/"execute"; approval statuses), never client input.
            "schema_version": AUDIT_SCHEMA_VERSION,
            "mcp_tool": mcp_tool,
            "mcp_approval_status": mcp_approval_status,
            # v3 fields. Always present; signed to prove that observe/allow modes were
            # evaluated and are preserved in the log. Callers pass actual enforcement
            # evidence; default (enforce/False/None) is used when not softening.
            "enforcement_mode": enforcement_mode,
            "would_deny": would_deny,
            "would_deny_reason_code": would_deny_reason_code,
        }

    def log_decision(
        self,
        *,
        request_id: str,
        sql: str,
        agent_id: str | None = None,
        parsed_sql: ParsedSQL,
        decision: PolicyDecision,
        remediation_present: bool,
        metadata: dict[str, Any] | None = None,
        rewrite_suggested: bool = False,
        agent_authenticated: bool = False,
        mcp_tool: str | None = None,
        mcp_approval_status: str | None = None,
        enforcement_mode: str = "enforce",
        would_deny: bool = False,
        would_deny_reason_code: str | None = None,
    ) -> None:
        """Log a tamper-proof audit event with cryptographic chaining."""

        global _last_signature, _sequence
        with _audit_lock:
            sequence = _sequence
            event = self._build_event(
                request_id=request_id,
                agent_id=agent_id,
                parsed_sql=parsed_sql,
                decision=decision,
                remediation_present=remediation_present,
                metadata=metadata,
                sql=sql,
                key=self._key,
                rewrite_suggested=rewrite_suggested,
                agent_authenticated=agent_authenticated,
                sequence=sequence,
                mcp_tool=mcp_tool,
                mcp_approval_status=mcp_approval_status,
                enforcement_mode=enforcement_mode,
                would_deny=would_deny,
                would_deny_reason_code=would_deny_reason_code,
            )
            signature = _sign_event(event, _last_signature, self._key)
            event["event_signature"] = signature
            event["previous_signature"] = _last_signature
            _last_signature = signature
            _sequence = sequence + 1
            # Decide checkpoint emission inside the lock so the captured head is
            # consistent with the event just written; emit the log line outside it.
            interval = self._settings.audit_checkpoint_interval or 0
            checkpoint_due = interval > 0 and _sequence % interval == 0
            head_sequence, head_signature = sequence, signature

        with bound_contextvars(request_id=request_id, agent_id=agent_id or "unknown"):
            self._logger.info("terminus_intercept_decision", **event)

        if checkpoint_due:
            self._emit_checkpoint(sequence=head_sequence, head_signature=head_signature)

    def log_trust_change(
        self,
        *,
        agent_id: str,
        previous_trust_level: str,
        new_trust_level: str,
        governance_version: str,
        trust_changed_by: str | None = None,
        trust_change_reason: str | None = None,
    ) -> None:
        """Log a tamper-proof, prev-chained record of an agent's trust-level change.

        Shares the same chain state (_audit_lock/_last_signature/_sequence) as
        log_decision: a promotion or demotion is just another link, so deleting or
        reordering it relative to surrounding decision events breaks the same HMAC
        chain and trips the same sequence-gap detection. Mirrors log_decision's
        lock/sign/emit structure deliberately; do not refactor log_decision to share
        code with this method, it would risk drifting the load-bearing decision path.
        """

        global _last_signature, _sequence
        with _audit_lock:
            sequence = _sequence
            event: dict[str, Any] = {
                "event_time": datetime.now(UTC).isoformat(),
                "agent_id": agent_id,
                "previous_trust_level": previous_trust_level,
                "new_trust_level": new_trust_level,
                "governance_version": governance_version,
                # `or` here also catches an empty-string provenance value (not just
                # None), intentionally: an agents.yaml entry with trust_changed_by: ""
                # is treated the same as an omitted field, never signed as a blank.
                "trust_changed_by": trust_changed_by or _UNSPECIFIED_PROVENANCE,
                "trust_change_reason": trust_change_reason or _UNSPECIFIED_PROVENANCE,
                "sequence": sequence,
                "schema_version": TRUST_CHANGE_SCHEMA_VERSION,
            }
            signature = _sign_event(event, _last_signature, self._key)
            event["event_signature"] = signature
            event["previous_signature"] = _last_signature
            _last_signature = signature
            _sequence = sequence + 1
            # Decide checkpoint emission inside the lock so the captured head is
            # consistent with the event just written; emit the log line outside it.
            interval = self._settings.audit_checkpoint_interval or 0
            checkpoint_due = interval > 0 and _sequence % interval == 0
            head_sequence, head_signature = sequence, signature

        with bound_contextvars(agent_id=agent_id):
            self._logger.info(TRUST_CHANGE_EVENT_NAME, **event)

        if checkpoint_due:
            self._emit_checkpoint(sequence=head_sequence, head_signature=head_signature)

    def _emit_checkpoint(self, *, sequence: int, head_signature: str) -> None:
        """Emit a signed checkpoint of the chain head as a distinct log line."""
        checkpoint = build_checkpoint(
            boot_id=_boot_id, sequence=sequence, head_signature=head_signature, key=self._key
        )
        self._logger.info(
            _CHECKPOINT_EVENT_NAME, **{k: v for k, v in checkpoint.items() if k != "event"}
        )
