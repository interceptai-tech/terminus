"""Tests for audit event schema constants and chain verification."""

from __future__ import annotations

import hashlib
import hmac
import io
import json

import pytest
import structlog

from terminus.audit import audit_logger as al
from terminus.audit.audit_logger import AUDIT_SIGNED_FIELDS, AuditLogger
from terminus.audit.verify import (
    AuditChainVerificationError,
    verify_audit_chain,
)
from terminus.config.settings import get_settings
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine


def _sample_event() -> dict:
    parsed = parse_sql("DROP TABLE public.users")
    engine = PolicyEngine.from_default_policy()
    decision = engine.evaluate(parsed, agent_id="analytics_agent_42")
    return AuditLogger._build_event(
        request_id="r1",
        agent_id="analytics_agent_42",
        parsed_sql=parsed,
        decision=decision,
        remediation_present=True,
        metadata={},
        sql="DROP TABLE public.users",
        key=get_settings().audit_hmac_key,
    )


def test_build_event_keys_match_signed_fields() -> None:
    assert set(_sample_event().keys()) == set(AUDIT_SIGNED_FIELDS)


# --- F8: the SQL digest must be keyed so it is not brute-forceable from logs ---
#
# A plain sha256(sql) is recoverable: SQL is low-entropy and structured, so an
# attacker with the shipped logs can dictionary/brute-force a PII literal (an SSN,
# an email) and confirm the query. The digest is now a keyed HMAC over a versioned
# domain tag, so recovery needs the secret audit key. It stays deterministic within
# a deployment so a SIEM can still correlate repeated queries.

_F8_SQL = "SELECT id, name FROM public.users WHERE ssn = '487-65-1234'"


def test_sql_digest_is_keyed_not_bare_sha256() -> None:
    from terminus.audit.audit_logger import sql_digest

    key = "x" * 40
    assert sql_digest(_F8_SQL, key) != hashlib.sha256(_F8_SQL.encode()).hexdigest()


def test_sql_digest_depends_on_the_key() -> None:
    from terminus.audit.audit_logger import sql_digest

    assert sql_digest(_F8_SQL, "a" * 40) != sql_digest(_F8_SQL, "b" * 40)


def test_sql_digest_is_deterministic_within_a_key() -> None:
    from terminus.audit.audit_logger import sql_digest

    key = "x" * 40
    assert sql_digest(_F8_SQL, key) == sql_digest(_F8_SQL, key)


def test_sql_digest_construction_is_domain_separated_hmac() -> None:
    # Pin the exact construction: HMAC(key, DOMAIN || sql), distinct from both a
    # bare sha256 and an un-tagged HMAC (so it can never collide with the chain or
    # checkpoint HMACs, which sign different message spaces under the same key).
    from terminus.audit.audit_logger import _SQL_DIGEST_DOMAIN, sql_digest

    key = "x" * 40
    expected = hmac.new(
        key.encode("utf-8"), _SQL_DIGEST_DOMAIN + _F8_SQL.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert sql_digest(_F8_SQL, key) == expected
    untagged = hmac.new(key.encode("utf-8"), _F8_SQL.encode("utf-8"), hashlib.sha256).hexdigest()
    assert sql_digest(_F8_SQL, key) != untagged


def test_sql_digest_fails_closed_on_empty_key() -> None:
    # HMAC with an empty key does NOT raise on its own (verified), so it would
    # silently produce an effectively-unkeyed, brute-forceable digest. The helper
    # must reject an empty key rather than fall back to an unkeyed hash.
    from terminus.audit.audit_logger import sql_digest

    with pytest.raises(ValueError):
        sql_digest(_F8_SQL, "")


def test_sql_digest_shape_leaks_no_sql() -> None:
    from terminus.audit.audit_logger import sql_digest

    digest = sql_digest(_F8_SQL, "x" * 40)
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
    for leak in ("users", "ssn", "487-65-1234", "SELECT"):
        assert leak not in digest


def test_old_plain_sha256_logs_still_verify() -> None:
    # Migration guarantee: changing the digest function does NOT break verification
    # of pre-F8 logs. The verifier re-signs the STORED sql_sha256 value; it never
    # recomputes sql_digest. A legacy event carrying a bare sha256 still verifies.
    from terminus.audit.audit_logger import GENESIS_SIGNATURE, _sign_event

    key = get_settings().audit_hmac_key
    legacy = _sample_event()
    legacy["sql_sha256"] = hashlib.sha256(b"DROP TABLE public.users").hexdigest()  # pre-F8 value
    legacy["previous_signature"] = GENESIS_SIGNATURE
    legacy["event_signature"] = _sign_event(
        {k: legacy[k] for k in AUDIT_SIGNED_FIELDS}, GENESIS_SIGNATURE, key
    )
    line = json.dumps({**legacy, "event": "terminus_intercept_decision"})
    result = verify_audit_chain([line], key, require_genesis=True)
    assert result.ok, result.failures


def test_sql_digest_not_recoverable_by_literal_bruteforce_without_key() -> None:
    # The behavioral property F8 is about: an attacker who knows the query template
    # and Terminus's (open-source) digest scheme but NOT the key cannot confirm the
    # secret literal by hashing candidates.
    from terminus.audit.audit_logger import sql_digest

    logged = sql_digest(_F8_SQL, "s3cr3t-deployment-key-at-least-32-bytes!")
    recovered = any(
        hashlib.sha256(
            f"SELECT id, name FROM public.users WHERE ssn = '487-65-{n:04d}'".encode()
        ).hexdigest()
        == logged
        for n in range(2000)
    )
    assert not recovered


def test_build_event_uses_event_time_not_timestamp() -> None:
    event = _sample_event()
    assert "event_time" in event
    assert "timestamp" not in event


def _emit_chain(sqls: list[str], *, after: object = None) -> list[str]:
    """Emit audit events through the REAL structlog pipeline into a buffer and
    return the rendered JSON lines. Mirrors configure_logging's processors so the
    test exercises the same rendering (including TimeStamper) production uses.

    ``after`` is an optional zero-arg callable run after the decisions are logged
    but before the buffer is read, so a test can exercise e.g. shutdown emission
    against the same live chain state.
    """
    buf = io.StringIO()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=buf),
        cache_logger_on_first_use=False,
    )
    try:
        # Reset the process-global audit chain head to GENESIS_SIGNATURE so the
        # emitted events form a clean chain from genesis. This assumes sequential
        # test execution (pytest default) and is not safe under parallel execution
        # such as pytest-xdist.
        al._last_signature = al.GENESIS_SIGNATURE
        al._sequence = 0
        logger = al.AuditLogger()
        engine = PolicyEngine.from_default_policy()
        for i, sql in enumerate(sqls):
            parsed = parse_sql(sql)
            decision = engine.evaluate(parsed, agent_id="analytics_agent_42")
            logger.log_decision(
                request_id=f"r{i}",
                sql=sql,
                agent_id="analytics_agent_42",
                parsed_sql=parsed,
                decision=decision,
                remediation_present=False,
            )
        if after is not None:
            after()
        return [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    finally:
        al.configure_logging()  # restore the production logging config


_SQLS = [
    "SELECT id FROM public.users WHERE id = 1",
    "DROP TABLE public.users",
    "UPDATE public.users SET name = 'x' WHERE id = 1",
]


def test_chain_verifies_from_rendered_logs() -> None:
    lines = _emit_chain(_SQLS)
    result = verify_audit_chain(lines, get_settings().audit_hmac_key, require_genesis=True)
    assert result.ok, result.failures
    assert result.verified_count == len(_SQLS)


def test_tampered_field_is_detected() -> None:
    lines = _emit_chain(_SQLS)
    event = json.loads(lines[1])
    event["decision"] = "allow"  # flip a signed field
    lines[1] = json.dumps(event)
    result = verify_audit_chain(lines, get_settings().audit_hmac_key, require_genesis=True)
    assert not result.ok
    assert any(f.reason == "signature_mismatch" and f.index == 1 for f in result.failures)


def test_dropped_line_breaks_linkage() -> None:
    lines = _emit_chain(_SQLS)
    del lines[1]  # drop a middle event
    result = verify_audit_chain(lines, get_settings().audit_hmac_key, require_genesis=True)
    assert not result.ok
    assert any(f.reason == "broken_link" for f in result.failures)


def test_suffix_verifies_with_start_signature() -> None:
    lines = _emit_chain(_SQLS)
    first = json.loads(lines[0])
    result = verify_audit_chain(
        lines[1:], get_settings().audit_hmac_key, start_signature=first["event_signature"]
    )
    assert result.ok, result.failures
    assert result.verified_count == len(_SQLS) - 1


def test_wrong_start_signature_is_anchor_mismatch() -> None:
    lines = _emit_chain(_SQLS)
    result = verify_audit_chain(
        lines[1:], get_settings().audit_hmac_key, start_signature="deadbeef"
    )
    assert not result.ok
    assert any(f.reason == "anchor_mismatch" and f.index == 0 for f in result.failures)


def test_require_genesis_conflicts_with_start_signature() -> None:
    with pytest.raises(ValueError):
        verify_audit_chain(["{}"], "k", require_genesis=True, start_signature="abc")


def test_non_json_line_raises_with_diagnostics() -> None:
    with pytest.raises(AuditChainVerificationError) as exc:
        verify_audit_chain(["not json at all"], "k")
    assert exc.value.line_index == 0
    assert exc.value.snippet is not None


def test_missing_signed_field_raises() -> None:
    lines = _emit_chain(_SQLS)
    event = json.loads(lines[0])
    del event["decision"]
    with pytest.raises(AuditChainVerificationError):
        verify_audit_chain([json.dumps(event)], get_settings().audit_hmac_key)


# --- F7: make truncation detectable (signed sequence + out-of-band head anchor) ---
#
# The HMAC chain proves internal consistency but records nothing about its expected
# length or current head, so dropping events off the END verifies clean. Two layers:
# (A) a signed monotonic `sequence` per event + verifier `expected_head_*` params
# that detect a short tail; (B) a signed checkpoint of the head shipped out-of-band.


def test_events_carry_contiguous_signed_sequence() -> None:
    lines = _emit_chain(_SQLS)
    seqs = [json.loads(ln)["sequence"] for ln in lines]
    assert seqs == [0, 1, 2]


def test_sequence_field_is_signed() -> None:
    # Tampering the sequence must break the signature (sequence is inside the HMAC).
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS)
    event = json.loads(lines[1])
    event["sequence"] = 99
    lines[1] = json.dumps(event)
    result = verify_audit_chain(lines, key, require_genesis=True)
    assert not result.ok
    assert any(f.reason == "signature_mismatch" and f.index == 1 for f in result.failures)


def test_tail_truncation_detected_with_expected_head() -> None:
    # The core F7 fix: drop the last event, but verify against the true head that a
    # SIEM captured out-of-band -> tail_truncation.
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS)
    head = json.loads(lines[-1])
    result = verify_audit_chain(
        lines[:-1],
        key,
        require_genesis=True,
        expected_head_signature=head["event_signature"],
        expected_head_sequence=head["sequence"],
    )
    assert not result.ok
    assert any(f.reason == "tail_truncation" for f in result.failures)


def test_expected_head_matches_clean_chain_is_ok() -> None:
    # The head anchor must not false-positive on an untampered chain.
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS)
    head = json.loads(lines[-1])
    result = verify_audit_chain(
        lines,
        key,
        require_genesis=True,
        expected_head_signature=head["event_signature"],
        expected_head_sequence=head["sequence"],
    )
    assert result.ok, result.failures
    assert result.verified_count == len(_SQLS)


def test_all_events_deleted_reported_as_tail_truncation() -> None:
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS)
    head = json.loads(lines[-1])
    result = verify_audit_chain(
        [],
        key,
        expected_head_signature=head["event_signature"],
        expected_head_sequence=head["sequence"],
    )
    assert not result.ok
    assert any(f.reason == "tail_truncation" for f in result.failures)


def test_middle_drop_also_reports_sequence_gap() -> None:
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS)
    del lines[1]
    result = verify_audit_chain(lines, key, require_genesis=True)
    assert not result.ok
    assert any(f.reason == "sequence_gap" for f in result.failures)


def test_checkpoint_roundtrip_verifies() -> None:
    from terminus.audit.audit_logger import build_checkpoint, verify_checkpoint

    key = get_settings().audit_hmac_key
    cp = build_checkpoint(boot_id="b0", sequence=41, head_signature="abc123", key=key)
    assert cp["event"] == "terminus_audit_checkpoint"
    assert cp["sequence"] == 41
    assert verify_checkpoint(cp, key) is True


def test_tampered_checkpoint_rejected() -> None:
    # An attacker who lowers the checkpoint's sequence to mask truncation must be
    # caught: the checkpoint is itself HMAC-signed.
    from terminus.audit.audit_logger import build_checkpoint, verify_checkpoint

    key = get_settings().audit_hmac_key
    cp = build_checkpoint(boot_id="b0", sequence=41, head_signature="abc123", key=key)
    cp["sequence"] = 40
    assert verify_checkpoint(cp, key) is False


# --- Reveal events (reveal_served / reveal_rejected): a second event type sharing
# the same chain, mirroring the trust-change event's mechanics exactly. ---


def test_build_reveal_event_keys_match_signed_fields() -> None:
    from terminus.audit.audit_logger import REVEAL_SIGNED_FIELDS

    event = AuditLogger._build_reveal_event(
        request_id="r1",
        reveal_id="rev-1",
        operator_id="op1",
        event_type="reveal_served",
        reason_code=None,
        sql_sha256="digest-1",
        bundle_sha256="bundle-digest-1",
    )
    assert set(event.keys()) == set(REVEAL_SIGNED_FIELDS)


def _emit_decision_and_reveal_chain() -> list[str]:
    """One log_decision then one log_reveal on the SAME chain (shared
    _audit_lock/_last_signature/_sequence), mirroring the trust-change
    interleaving test: proves the two event kinds link and verify together."""
    buf = io.StringIO()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=buf),
        cache_logger_on_first_use=False,
    )
    try:
        al._last_signature = al.GENESIS_SIGNATURE
        al._sequence = 0
        logger = al.AuditLogger()
        parsed = parse_sql(_SQLS[0])
        decision = PolicyEngine.from_default_policy().evaluate(
            parsed, agent_id="analytics_agent_42"
        )
        logger.log_decision(
            request_id="r1",
            sql=_SQLS[0],
            agent_id="analytics_agent_42",
            parsed_sql=parsed,
            decision=decision,
            remediation_present=False,
        )
        logger.log_reveal(
            request_id="r1",
            reveal_id="rev-1",
            operator_id="op1",
            event_type="reveal_served",
            reason_code=None,
            sql_sha256="digest-1",
            bundle_sha256="bundle-digest-1",
        )
        return [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    finally:
        al.configure_logging()  # restore the production logging config


def test_decision_and_reveal_chain_round_trips() -> None:
    lines = _emit_decision_and_reveal_chain()
    result = verify_audit_chain(lines, get_settings().audit_hmac_key, require_genesis=True)
    assert result.ok, result.failures
    assert result.verified_count == 2


def test_periodic_checkpoints_capture_head(monkeypatch, reset_auth_caches) -> None:
    # With an interval of 2, emitting 4 decisions must drop a signed checkpoint of
    # the head after events 1 and 3, so a SIEM can capture the head out-of-band.
    from terminus.audit.audit_logger import verify_checkpoint

    monkeypatch.setenv("TERMINUS_AUDIT_CHECKPOINT_INTERVAL", "2")
    reset_auth_caches()
    key = get_settings().audit_hmac_key
    lines = _emit_chain(["SELECT id FROM public.users WHERE id = 1"] * 4)

    parsed = [json.loads(ln) for ln in lines]
    decisions = [e for e in parsed if e.get("event") == "terminus_intercept_decision"]
    checkpoints = [e for e in parsed if e.get("event") == "terminus_audit_checkpoint"]

    assert [c["sequence"] for c in checkpoints] == [1, 3]
    assert all(verify_checkpoint(c, key) for c in checkpoints)
    head_sig_by_seq = {d["sequence"]: d["event_signature"] for d in decisions}
    assert checkpoints[0]["head_signature"] == head_sig_by_seq[1]
    assert checkpoints[1]["head_signature"] == head_sig_by_seq[3]


def test_checkpoint_interval_zero_disables_emission(reset_auth_caches) -> None:
    # Default (0) must emit no checkpoints, so the feature is opt-in.
    reset_auth_caches()
    lines = _emit_chain(_SQLS)
    assert not [ln for ln in lines if json.loads(ln).get("event") == "terminus_audit_checkpoint"]


def test_partial_expected_head_anchor_raises() -> None:
    # F7 re-review: an incomplete anchor must fail closed, not silently degrade to
    # a weaker check. A sequence without its signature previously let a divergent
    # longer segment pass; require both or neither.
    with pytest.raises(ValueError):
        verify_audit_chain(["{}"], "k", expected_head_sequence=5)
    with pytest.raises(ValueError):
        verify_audit_chain(["{}"], "k", expected_head_signature="abc")


def test_divergent_longer_chain_fails_expected_head(reset_auth_caches) -> None:
    # F7 review (Codex Finding 1): the chain re-roots at genesis every restart, so
    # the same key signs many valid segments. An attacker who deletes the anchored
    # segment and presents a DIFFERENT, longer valid segment must not pass: the
    # captured head must actually appear in the verified chain, not merely be a
    # lower sequence bound.
    reset_auth_caches()
    key = get_settings().audit_hmac_key
    seg_a = _emit_chain(
        [
            "SELECT id FROM public.users WHERE id = 1",
            "SELECT id FROM public.users WHERE id = 2",
        ]
    )
    head_a = json.loads(seg_a[-1])  # captured head at sequence 1
    seg_b = _emit_chain(
        [
            "SELECT id FROM public.orders WHERE id = 7",
            "SELECT id FROM public.orders WHERE id = 8",
            "SELECT id FROM public.orders WHERE id = 9",
            "SELECT id FROM public.orders WHERE id = 10",
        ]
    )
    assert json.loads(seg_b[1])["event_signature"] != head_a["event_signature"]
    result = verify_audit_chain(
        seg_b,
        key,
        require_genesis=True,
        expected_head_signature=head_a["event_signature"],
        expected_head_sequence=head_a["sequence"],
    )
    assert not result.ok
    assert any(f.reason == "tail_truncation" for f in result.failures)


def test_expected_head_in_start_signature_window_ok(reset_auth_caches) -> None:
    # F7 re-review Finding 2: the head anchor is the TO anchor and must be inside
    # the verified lines. A start_signature-anchored window whose head IS in the
    # window (the normal chunked-verification shape) must verify clean, not
    # false-positive tail_truncation.
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS)  # sequences 0, 1, 2
    first = json.loads(lines[0])
    head = json.loads(lines[-1])  # in-window head at sequence 2
    result = verify_audit_chain(
        lines[1:],  # window starts at sequence 1, anchored to event 0's signature
        key,
        start_signature=first["event_signature"],
        expected_head_signature=head["event_signature"],
        expected_head_sequence=head["sequence"],
    )
    assert result.ok, result.failures
    assert result.verified_count == len(_SQLS) - 1


def test_longer_same_chain_with_earlier_head_ok(reset_auth_caches) -> None:
    # Guard against over-correcting: a chain that legitimately GREW past the
    # captured checkpoint (same segment) must still verify. The captured head's
    # signature genuinely appears at its sequence, so there is no truncation.
    reset_auth_caches()
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS)  # sequences 0, 1, 2
    mid = json.loads(lines[1])  # captured head at sequence 1, chain later grew to 2
    result = verify_audit_chain(
        lines,
        key,
        require_genesis=True,
        expected_head_signature=mid["event_signature"],
        expected_head_sequence=mid["sequence"],
    )
    assert result.ok, result.failures
    assert result.verified_count == len(_SQLS)


def test_shutdown_checkpoint_captures_final_head(monkeypatch, reset_auth_caches) -> None:
    # A large interval means no periodic checkpoint fires for 3 events; the shutdown
    # checkpoint must still capture the final head so the tail is not left exposed.
    from terminus.audit.audit_logger import emit_shutdown_checkpoint, verify_checkpoint

    monkeypatch.setenv("TERMINUS_AUDIT_CHECKPOINT_INTERVAL", "1000")
    reset_auth_caches()
    key = get_settings().audit_hmac_key
    lines = _emit_chain(_SQLS, after=emit_shutdown_checkpoint)

    parsed = [json.loads(ln) for ln in lines]
    checkpoints = [e for e in parsed if e.get("event") == "terminus_audit_checkpoint"]
    decisions = [e for e in parsed if e.get("event") == "terminus_intercept_decision"]
    assert len(checkpoints) == 1
    assert checkpoints[0]["sequence"] == len(_SQLS) - 1  # head = last decision's sequence
    assert checkpoints[0]["head_signature"] == decisions[-1]["event_signature"]
    assert verify_checkpoint(checkpoints[0], key)
