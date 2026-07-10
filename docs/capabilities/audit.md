# Tamper-Evident Audit Log

A cryptographically chained record of every decision Terminus makes, for SOC 2,
GDPR, HIPAA, and 2am forensics. Configuration is in
[docs/configuration.md](../configuration.md).

## What it does

Every intercept decision (allow and deny) is written as a structured event on the
`terminus.audit` stream, emitted as the `terminus_intercept_decision` log line.
Each event is HMAC-SHA256 signed, and the signature includes the previous event's
signature, forming a verifiable chain. Removing, reordering, or altering any
event breaks the chain from that point forward.

A second event kind, `terminus_trust_level_change`, shares the same chain (see
below): graduated-autonomy trust promotions and demotions are signed and linked
in with decision events rather than kept in a separate, unlinked log.

Crucially, **raw SQL is never recorded**, only a keyed HMAC-SHA256 digest. The
audit log is forensically useful without itself becoming a place sensitive query
text leaks.

## What an event records

```json
{
  "event_time": "2026-06-20T14:22:31.847Z",
  "sequence": 0,
  "request_id": "1f0c...",
  "agent_id": "analytics_agent_42",
  "agent_authenticated": true,
  "decision": "deny",
  "reason": "Matched policy: Block destructive ...",
  "reason_code": "policy_rule",
  "policy_id": "block_all_destructive_operations",
  "operation": "DROP",
  "tables": ["public.users"],
  "risk_score": 1.0,
  "risk_reasons": ["destructive_operation"],
  "remediation_present": true,
  "rewrite_suggested": false,
  "sql_sha256": "e3b0c442...",
  "security_flags": { "has_smuggling_pattern": false, "...": false },
  "metadata_keys": ["tenant", "trace"],
  "schema_version": 3,
  "mcp_tool": null,
  "mcp_approval_status": null,
  "enforcement_mode": "enforce",
  "would_deny": false,
  "would_deny_reason_code": null,
  "previous_signature": "0000...",
  "event_signature": "9f3a..."
}
```

Two time fields appear on the line: `event_time` is the authoritative, signed
event time (covered by the HMAC); `timestamp` is the structlog log-render time
and is not part of the signature. Verify against `event_time`.

Notes on the privacy-preserving fields:

- `sql_sha256` is the only representation of the query, and it is now a keyed
  HMAC-SHA256 digest, HMAC'd over the SQL with `TERMINUS_AUDIT_HMAC_KEY`, not a
  bare hash: the query text itself is never present, and the digest cannot be
  reversed or dictionary-attacked without that key. It stays deterministic
  within a single deployment (same key), so a SIEM can still correlate repeated
  identical queries, but it differs across deployments and after key rotation,
  so cross-deployment correlation on this field no longer works, which is
  intended and privacy-positive. In `development` the shipped default key is
  public, so dev-mode digests are still guessable; this protection depends on a
  real `TERMINUS_AUDIT_HMAC_KEY`.
- `agent_authenticated` is true when the id came from a verified JWT (vs the
  self-asserted path).
- `metadata_keys` records only the **key names** of the request metadata, never
  the values.

### Schema versions (v2 and v3)

- `schema_version` (int): the signed payload schema version, `3` as of this
  change. Lines written without it are v1 (pre-2026-07-07); the verifier
  checks them against a frozen v1 field set rather than treating a missing
  field as an error, so pre-v2 history keeps verifying. Lines with `2` are
  checked against a frozen v2 field set the same way.
- `mcp_tool` (string or null, v2): which MCP tool ran, `"query"` or `"execute"`.
  `null` on HTTP `/intercept` events, which have no MCP tool.
- `mcp_approval_status` (string or null, v2): the break-glass outcome for the
  call, one of `pending_approval`, `approved`, `approval_denied`,
  `approval_expired`, `denied`. `null` when the call involved no approval
  interaction (an immediate allow, or an HTTP `/intercept` event).
- `enforcement_mode` (string, v3): the enforcement mode in effect for the
  decision. Default `"enforce"`; populated with other modes by graduated
  autonomy, which is being added on this branch.
- `would_deny` (bool, v3): whether enforce mode would have denied a request
  that a softer mode let through. Default `false`.
- `would_deny_reason_code` (string or null, v3): the stable reason code the
  would-be denial carried. Default `null` when `would_deny` is false.

The verifier picks the signed field set per line from its `schema_version`: a
line with no `schema_version` is checked against the v1 set, a line with
`schema_version: 2` against the frozen v2 set, a line with `schema_version: 3`
against the full v3 set including all six fields above, and any other value
fails closed with `unknown_schema_version` rather than being skipped or guessed
at. Stripping or editing any versioned field on a line, the same as any other
signed field, changes the payload the HMAC was computed over and surfaces as
`signature_mismatch`.

## The trust-change event (a second, chained event kind)

Graduated autonomy (see
[docs/capabilities/graduated-autonomy.md](graduated-autonomy.md)) promotes or
demotes an agent's per-agent trust level via a GitOps edit to `agents.yaml`
plus a config reload. Every applied reload that changes an agent's effective
`trust_level` emits one `terminus_trust_level_change` event per changed agent,
signed and linked into the SAME chain as `terminus_intercept_decision` events
(same `_audit_lock` / `_last_signature` / `_sequence` machinery in
`AuditLogger`), not a separate log or a separate signature space. Deleting,
reordering, or tampering with a trust-change event breaks the one running
chain exactly like tampering with a decision event does.

```json
{
  "event_time": "2026-07-07T09:15:02.113Z",
  "agent_id": "onboarding_agent_9",
  "previous_trust_level": "observe",
  "new_trust_level": "enforce",
  "governance_version": "a1b2c3d4e5f6",
  "trust_changed_by": "will@example.com",
  "trust_change_reason": "two weeks clean would_deny evidence",
  "sequence": 42,
  "schema_version": 1,
  "previous_signature": "9f3a...",
  "event_signature": "7c21..."
}
```

`TRUST_CHANGE_SIGNED_FIELDS` (the event's frozen signed field set): `event_time`,
`agent_id`, `previous_trust_level`, `new_trust_level`, `governance_version`,
`trust_changed_by`, `trust_change_reason`, `sequence`, `schema_version`.
`trust_changed_by` and `trust_change_reason` are optional in `agents.yaml`; when
omitted, the signed value is the literal `"unspecified: see git history"`
rather than `null`, so the signed field is always present. `governance_version`
is the reload's combined config hash (truncated), correlating the trust change
to the exact `policy.yaml` + `schema_whitelist.yaml` + `agents.yaml` bytes that
were active when it was applied. A brand-new agent added straight into
`agents.yaml` with `trust_level: observe` also emits an event, with
`previous_trust_level: "unregistered"`; removing or disabling an agent emits
nothing (a revoked agent is rejected by auth, which is already stricter than
any trust level). The initial snapshot built at process startup is the genesis
baseline and never emits a trust-change event, only a runtime reload diff does.

**This event has its OWN schema-version axis, independent of
`AUDIT_SCHEMA_VERSION`.** `schema_version: 1` on a `terminus_trust_level_change`
line means "the trust-change event's v1 field set" (`TRUST_CHANGE_SIGNED_FIELDS`
above), a completely separate number line from the `schema_version: 3` on a
`terminus_intercept_decision` line. The two event kinds evolve their field sets
independently; only the event's own `event` name says which schema-version
table applies. Domain separation between the two kinds rests on their signed
field-name sets being disjoint by construction (no shared field name means a
signed decision payload and a signed trust-change payload can never collide or
be replayed as each other), so any future schema author adding a field to one
event kind must not reuse a field name from the other's signed set.

**Verifier consequence: field-set selection is per event NAME, then per
`schema_version`.** `verify_audit_chain` dispatches on the JSON line's `event`
key first (`terminus_intercept_decision` vs `terminus_trust_level_change`,
anything else is skipped as before, e.g. `terminus_audit_checkpoint`), then
selects that event kind's signed field set for the line's `schema_version`. A
decision line and a trust-change line can interleave freely: both carry
`sequence`/`event_signature`/`previous_signature` against the SAME running
`prev_signature`, so a mixed decision/trust-change chain verifies as one
sequence, and deleting or reordering either kind trips the same
`broken_link`/`sequence_gap` checks described above. An unrecognized
`schema_version` on a trust-change line fails closed with
`unknown_schema_version`, exactly like an unrecognized decision-line version.

## How the chain works

- Each event is canonicalized (sorted-key JSON) and signed as
  `HMAC(key, previous_signature + event)`, with the result stored as
  `event_signature` and carried into the next event as `previous_signature`.
- The first event chains from a fixed genesis signature (`0` repeated 64 times).
- The signing key is `TERMINUS_AUDIT_HMAC_KEY`.
- Every event also carries a monotonic `sequence` integer inside the
  HMAC-signed fields. It starts at 0 for each process lifetime (the chain
  re-roots at genesis on restart, so each process is one segment) and
  increments by 1 per event; tampering with it breaks the event's signature
  like any other signed field.

To verify a log, use the bundled helper, which reconstructs each signed payload by
selecting the known `AUDIT_SIGNED_FIELDS` from the line (so structlog-added keys
like `timestamp`, `level`, and `event` are ignored) and recomputes the HMAC with
the same signer Terminus uses:

```python
from terminus.audit.verify import verify_audit_chain

result = verify_audit_chain(open("audit.log"), hmac_key, require_genesis=True)
assert result.ok, result.failures
```

Note: an empty or zero-event input returns `ok=True` with `verified_count == 0`, meaning
"no audit events were found, nothing to verify," NOT "a chain was verified." A consumer
such as a SIEM job should treat this as inconclusive (check `verified_count > 0`), not a pass.

`verify_audit_chain` is O(n) and streamable; verify a recent window by anchoring
on the prior chain head with `start_signature=<previous chunk's last event_signature>`
rather than replaying the whole history. Each `AuditChainFailure` names the index,
the reason (`signature_mismatch`, `broken_link`, `anchor_mismatch`, `sequence_gap`,
`tail_truncation`), and the expected vs actual value, so a mismatch localizes
exactly where the log diverged.

## How truncation detection works

Chaining alone proves internal consistency (no event was altered, reordered, or
inserted) but says nothing about the chain's expected length. An attacker who
can write the log store could delete the most recent events ("tail
truncation") and the remaining chain still verified clean, since a shorter
valid prefix is still a valid chain. Two mechanisms close that gap:

- **Signed `sequence`** (see above). The verifier checks that `sequence`
  increases by exactly 1 between consecutive events and reports `sequence_gap`
  on a break; this also catches a deletion or reorder in the middle of the
  chain, not just at the tail.
- **Out-of-band head checkpoints.** Terminus can emit a distinct,
  itself-HMAC-signed `terminus_audit_checkpoint` log line carrying the current
  chain head: `boot_id`, `sequence`, `head_signature`, and `checkpoint_time`. It
  is emitted every `TERMINUS_AUDIT_CHECKPOINT_INTERVAL` decision events (see
  [docs/configuration.md](../configuration.md); default `0` is disabled) and
  once more on graceful shutdown. Shipping this as a distinct, separately
  captured line matters because of trust domain: a downstream SIEM or
  aggregator captures it somewhere the log-store attacker does not control
  (see [docs/audit-to-siem.md](../audit-to-siem.md)).

`verify_audit_chain` gained two optional parameters, `expected_head_signature`
and `expected_head_sequence`, symmetric to the existing `start_signature` but
checked against the tail instead of the start:

```python
result = verify_audit_chain(
    open("audit.log"),
    hmac_key,
    expected_head_signature=captured_checkpoint.head_signature,
    expected_head_sequence=captured_checkpoint.sequence,
)
```

When the operator passes the last captured checkpoint's head, a chain that
falls short of it fails with `tail_truncation`. Existing callers that pass
neither parameter are unaffected.

**Known limits / residual window.** A hash chain cannot prove its own missing
suffix. Tail-truncation detection works only to the extent the head checkpoint
is captured somewhere the attacker cannot rewrite, an external SIEM, not the
same mutable log store or local volume. The residual exposure window is the
set of events written since the last *captured* checkpoint; a smaller
`TERMINUS_AUDIT_CHECKPOINT_INTERVAL` shrinks that window at the cost of more
checkpoint lines. Per-event durable anchoring (an fsync per request) was
deliberately rejected: it would violate the < 2 ms p99 latency budget.
Whole-segment deletion before any checkpoint is captured is mitigated
operationally by liveness monitoring: a running instance that emits no
decisions or checkpoints is itself an alert. A checkpoint is signed for
authenticity but is not self-freshening, so the verifier must always anchor to
the highest `sequence` captured per `boot_id`; accepting an older valid
checkpoint would downgrade the expected head and hide everything logged since.

## How to use

- **Set a real `TERMINUS_AUDIT_HMAC_KEY`** (>= 32 bytes) in production. The
  default is published in this repo, with it, the chain is forgeable and proves
  nothing. There is no error if you leave the default; the symptom is silent (a
  worthless chain), so treat this as a must-do.
- **Keep the key stable.** Rotating it breaks chain continuity across the
  rotation point (events before and after no longer verify as one chain). If you
  must rotate, treat the rotation as a documented chain boundary.
- **Upgrading to signed `sequence`.** Audit logs written before this change lack
  the `sequence` field and cannot be verified by the upgraded verifier. Treat the
  upgrade itself as a chain boundary, the same as a restart or key rotation
  already re-roots the chain.
- **Ship the stream** to your SIEM or log store like any structured log; the
  events are JSON with stable field names. See
  [docs/audit-to-siem.md](../audit-to-siem.md) for a runbook (a Vector/Splunk
  example, the fields to alert on, and the scheduled integrity check).
- The current event is intentionally lean (decision metadata + digest). A fuller
  schema (event_id, session_id, trace_id, latency_ms, source ip/user-agent) is a
  documented future enhancement. The HMAC chain is process-scoped: it starts from
  genesis on each restart and does not yet span restarts (durable chain-head storage
  is a planned enhancement).
