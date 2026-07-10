# Shipping Terminus Audit Logs to a SIEM

A short runbook for centralizing the tamper-evident audit stream into Splunk,
Elastic, Datadog, or Microsoft Sentinel. Field reference:
[docs/capabilities/audit.md](capabilities/audit.md).

## What you are shipping

Terminus writes each decision as the `terminus_intercept_decision` log line on the
`terminus.audit` stream: structured JSON, stable field names, to stdout (and/or a
file). Raw SQL is never present, only `sql_sha256`, a keyed HMAC-SHA256 digest
that is not dictionary-reversible without the deployment's
`TERMINUS_AUDIT_HMAC_KEY`, so the stream is safe to centralize without leaking
query text or data.

## The pattern

```
Terminus stdout/file -> log agent (Vector / Fluent Bit / Filebeat) -> your SIEM
```

Treat it like any structured application log. There is no special integration.

## Example: Vector to Splunk HEC

```toml
[sources.terminus]
type = "docker_logs"                 # or: type = "file", include = ["/var/log/terminus/audit.log"]
include_containers = ["terminus"]

[transforms.audit_only]
type = "filter"
inputs = ["terminus"]
condition = 'contains(string!(.message), "terminus_intercept_decision")'

[transforms.parse]
type = "remap"
inputs = ["audit_only"]
source = '. = parse_json!(.message)'

[sinks.splunk]
type = "splunk_hec_logs"
inputs = ["parse"]
endpoint = "https://splunk.example.com:8088"
default_token = "${SPLUNK_HEC_TOKEN}"
index = "terminus_audit"
```

For Elastic, swap the sink for `elasticsearch`; for Datadog or Sentinel, use their
respective sinks. The source and parse steps are unchanged.

## Fields worth indexing and alerting on

- `agent_id`, `agent_authenticated` (alert on `false` in production: a self-asserted agent slipped through unverified)
- `decision`, `reason_code`, `policy_id`
- `risk_score`, `risk_reasons`, `security_flags`
- `operation`, `tables`
- `sql_sha256` (correlate repeated queries within this deployment, without ever
  seeing the query text; the digest is keyed per deployment, so it will not
  match across deployments or after a key rotation)
- `event_signature` (the chain head for the integrity check below)
- `schema_version` (signed payload schema version, `3` as of this change; a
  line with none is v1 (pre-2026-07-07), `2` is the MCP-context addition)
- `mcp_tool` (`"query"` or `"execute"`; `null` on HTTP `/intercept` events)
- `mcp_approval_status` (break-glass outcome: `pending_approval`, `approved`,
  `approval_denied`, `approval_expired`, `denied`; `null` when the call
  involved no approval interaction)
- `enforcement_mode` (`"observe"` or `"enforce"`, v3, graduated autonomy)
- `would_deny` (bool, v3): true when a decision that executed (`decision=allow`)
  would have been denied under enforce
- `would_deny_reason_code` (string or null, v3): the ORIGINAL deny reason code
  when `would_deny` is true

Useful detections: a spike in `decision = deny`, any `agent_authenticated = false`,
a high `risk_score` that was still `allow` (a policy gap), a rising rate of
`would_deny = true` for an agent you expect to already be enforced (means its
registry entry drifted to `observe`, or graduated autonomy is masking real
denies you should be seeing), and smuggling flags firing.

**Pre-v2 lines lack the `schema_version`/`mcp_tool`/`mcp_approval_status` trio
entirely, not just null values, and pre-v3 lines lack the `enforcement_mode` /
`would_deny` / `would_deny_reason_code` trio the same way.** A log line written
before schema v2 has no `schema_version`, `mcp_tool`, or `mcp_approval_status`
key at all; a line written before schema v3 (schema_version absent, or `2`) has
no `enforcement_mode`, `would_deny`, or `would_deny_reason_code` key at all
either, even though it was written correctly for its schema at the time. Build
any SIEM query, dashboard, or alert against these fields so it tolerates
absence: coalesce the field to null, or use a has()/exists()-style check,
rather than assuming the key is always present. In particular, do not build a
"count of would-be-denied requests" dashboard that silently reads absent
`would_deny` as `false`; treat it as unknown/not-applicable for pre-v3 lines
instead, or the older segment of history will look artificially clean.

## Alert on trust-level changes (graduated autonomy)

A promotion or demotion is a security-posture change, an agent moving between
observe (denies get softened to allow-with-evidence) and enforce, and belongs
on the same "notify a human" tier as any other privilege change, not buried in
routine decision volume. Terminus writes it as its own event kind,
`terminus_trust_level_change`, into the SAME HMAC chain as
`terminus_intercept_decision` events; see
[docs/capabilities/audit.md](capabilities/audit.md) for the full field
reference and how one chain covers both kinds.

- **Widen your log-shipping filter to include it.** The example Vector
  transform above filters on `terminus_intercept_decision` only; a
  `terminus_trust_level_change` line would be silently dropped by that same
  `contains()` condition. Match on both event names (or ship the whole
  `terminus.audit` stream unfiltered and let the SIEM query narrow later).
- **Alert on every occurrence**, not on a rate or threshold: fields worth
  surfacing in the alert are `agent_id`, `previous_trust_level`,
  `new_trust_level`, `trust_changed_by`, `trust_change_reason`, and
  `governance_version` (correlates the change to the exact config bytes
  active at that moment). A `new_trust_level: "observe"` on an agent that
  handles anything destructive is worth flagging even harder, since it means
  some deny classes for that agent are now being softened to allow.
- **Verify it like any other chain event**, not separately: it carries the
  same `sequence` / `event_signature` / `previous_signature` fields as a
  decision line, so `verify_audit_chain` catches a deleted or reordered
  promotion event the same way it catches a deleted decision (see
  [docs/capabilities/audit.md](capabilities/audit.md)).

## Preserve verifiability

The HMAC chain is order-dependent, so the value of "tamper-evident" depends on how
you ship it. Three rules:

1. **Do not reorder or drop events in the pipeline.** Ship in emission order. A SIEM
   that reindexes by its own ingest time is fine for search, but keep the raw,
   ordered stream too (or run the integrity check before ingest).
2. **Verify on a schedule.** Run `verify_audit_chain` over a recent window, anchored
   on the previous window's last `event_signature` so you do not replay all history:

```python
from terminus.audit.verify import verify_audit_chain

result = verify_audit_chain(window_lines, hmac_key, start_signature=prev_chain_head)
if not result.ok:
    alert(result.failures)          # each failure names the exact index + reason
elif result.verified_count == 0:
    alert("no audit events in window: inconclusive, not a pass")
```

3. **Capture the head checkpoint outside the mutable audit stream, then verify
   against it.** Route each `terminus_audit_checkpoint` record (carrying
   `boot_id`, `sequence`, `head_signature`, `checkpoint_time`) and/or the
   current running head to storage the audit-stream attacker does not control,
   a separate index, a different retention target, or your alerting/config
   system. When you verify, pass the last captured head as
   `expected_head_sequence` and `expected_head_signature`:

```python
result = verify_audit_chain(
    window_lines,
    hmac_key,
    start_signature=prev_chain_head,
    expected_head_sequence=last_captured_checkpoint.sequence,
    expected_head_signature=last_captured_checkpoint.head_signature,
)
```

   A chain that falls short of the captured head, or that reaches the captured
   sequence with a different signature (a divergent or substituted segment),
   fails with `tail_truncation`; a broken `sequence` continuity (including a
   deletion or reorder in the middle) fails with `sequence_gap`. Alert on both.

   `start_signature` is the older FROM anchor (the predecessor the window
   continues from, not itself in the lines); `expected_head_*` is the newer TO
   anchor and must fall WITHIN the lines you pass, so its presence can be proven.
   When verifying a long history in `start_signature`-anchored chunks, pass the
   head only on the chunk that contains it (normally the last). Pass both head
   parameters together: an incomplete anchor is rejected rather than silently
   downgraded to a weaker length-only check.

   **Always verify against your freshest captured head, per `boot_id`.** A
   checkpoint is HMAC-signed for authenticity but carries no freshness of its
   own, so a genuine but older checkpoint (lower `sequence`) is still valid.
   Storing checkpoints append-only and always selecting the highest `sequence`
   for a given `boot_id` prevents an attacker from presenting a stale checkpoint
   to downgrade the expected head and hide everything logged since. Reject any
   presented checkpoint older than the latest you have captured for that
   `boot_id`.

Treat `verified_count == 0` as inconclusive (no events found), never as a pass.

**Liveness as a backstop.** Truncation detection depends on a checkpoint having
been captured. A whole segment deleted before any checkpoint was captured would
not be caught by verification alone; mitigate operationally with liveness
monitoring, a running Terminus instance that emits no decisions and no
checkpoints for an extended period is itself an alert condition.

## Two must-dos, or the chain proves nothing

- **Set a real `TERMINUS_AUDIT_HMAC_KEY` (at least 32 bytes).** The shipped default is
  public; with it, the chain is forgeable and proves nothing. (Terminus now refuses
  to start with a too-short key.)
- **Keep the key stable.** Rotating it breaks chain continuity; treat any rotation as
  a documented chain boundary.

## Known limits today

- The chain is process-scoped: it restarts from genesis on each Terminus restart, so
  treat each restart as a chain boundary for now (durable chain-head storage that
  spans restarts is a planned enhancement).
- The event schema is intentionally lean (decision, risk, digest). A fuller schema
  (session_id, trace_id, latency, source IP / user-agent) is planned.
- Tail-truncation detection is only as strong as the checkpoint capture: the
  residual exposure window is whatever was written since the last checkpoint
  your SIEM actually captured. A smaller `TERMINUS_AUDIT_CHECKPOINT_INTERVAL`
  shrinks that window at the cost of more checkpoint lines.
