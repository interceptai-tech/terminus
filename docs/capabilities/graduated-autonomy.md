# Graduated Autonomy (per-agent observe to enforce)

A write-confidence adoption path: register a new or uncertain agent in
observe mode, let Terminus record what it WOULD deny without blocking the
agent, review that evidence, then promote the agent to enforce with a
GitOps edit and a config reload. Every promotion is a signed, auditor-visible
event in the same HMAC chain as decisions. Configuration is in
[docs/configuration.md](../configuration.md); the security framing is in
SECURITY.md; audit event fields are in [docs/capabilities/audit.md](audit.md).

## What it does

`policy_engine.evaluate()` stays trust-unaware: it always computes the same
allow/deny it always has (`src/terminus/policy/policy_engine.py`). Graduated
autonomy is a transform that runs immediately AFTER `evaluate()` returns, on
both enforcement surfaces, and may only convert specific deny reasons into an
allow for an agent an operator has explicitly marked `observe`
(`src/terminus/policy/graduated.py`). It never loosens the whitelist, the
policy rules, or the parser; it decides, per request, whether an existing
deny is allowed to execute anyway, with the original deny preserved as
evidence.

The whole feature is gated by one master switch,
`TERMINUS_GRADUATED_AUTONOMY_ENABLED` (default `false`). Off, `trust_level`
in the registry has zero effect and every agent behaves exactly as it does
today (`resolve_enforcement_mode` returns `"enforce"` unconditionally; see
`src/terminus/policy/graduated.py:39-40`).

## The trust model

### Where trust lives

`AgentEntry.trust_level` (`src/terminus/auth/registry.py`) is an optional
field on each `agents.yaml` entry:

```yaml
agents:
  - id: onboarding_agent_9
    description: "Example observe-mode agent being evaluated for promotion"
    trust_level: observe        # observe | enforce; absent means enforce
```

`AgentRegistry.trust_of(agent_id)` (`src/terminus/auth/registry.py`)
resolves the effective trust for an id. The registry rides the same
hot-reloadable `GovernanceSnapshot` as the policy engine and schema
whitelist (`src/terminus/config/governance.py`): a promotion is an
`agents.yaml` edit plus a reload, never a restart, and a validation failure
on reload keeps the entire last-known-good snapshot (registry included).

### Fail-safe defaults (never weaker by accident)

`trust_of` and `resolve_enforcement_mode` both resolve to `"enforce"` in
every ambiguous case. Nothing here is a coincidence of missing config; each
is a deliberate fail-closed default:

| Condition | Effective mode | Why |
|---|---|---|
| `trust_level` field absent on the entry | `enforce` | the `AgentEntry.trust_level` Pydantic field default is `"enforce"` (`registry.py`); "starts observe" is an operator action, never a code default |
| Unknown / unregistered `agent_id` | `enforce` | `trust_of` falls through its loop to a final `return "enforce"` (`registry.py`); a typo'd id or a removed entry can never soften a deny |
| Agent `status: disabled` | `enforce` | `trust_of` only returns the stored `trust_level` when `status == "active"` (`registry.py`); a revoked agent is never softened |
| Unauthenticated request (no verified JWT) | `enforce` | `resolve_enforcement_mode` short-circuits to `"enforce"` whenever `agent_authenticated` is `False` or `agent_id is None` (`graduated.py:41-42`), regardless of what the registry says for that id |
| Malformed `trust_level` value in `agents.yaml` | reload rejected | Pydantic only accepts the `Literal["observe", "enforce"]`; any other value fails validation, so `reload_now()` keeps the last-known-good snapshot rather than applying a bad config (`governance.py:167-176`) |
| `TERMINUS_GRADUATED_AUTONOMY_ENABLED=false` (the default) | `enforce` | `resolve_enforcement_mode` returns `"enforce"` before consulting the registry at all (`graduated.py:39-40`); switch-off is byte-for-byte equivalent to every agent being `enforce` |

## Softening semantics: an allowlist, not a denylist

`OBSERVE_SOFTENABLE` (`src/terminus/policy/graduated.py:24-26`) is the
complete, frozen list of deny `reason_code`s an observe agent can have
softened to an allow:

- `schema_whitelist`
- `column_whitelist`
- `policy_rule`
- `risk_threshold`
- `default`

Every other deny `reason_code` stays a deny for an observe agent, through
one of two distinct mechanisms:

**Engine-level floor codes** reach `soften_if_observing` but are not on the
allowlist, so the transform returns the deny unchanged; there is no config
to change that. As of this writing:

- `invalid_sql`
- `oversize_sql`
- `multi_statement`
- `injection_function`
- `nested_write`
- `wrong_tool` (MCP-only; see below)

**Post-decision guardrail deny codes** are produced AFTER the transform has
already run, by guardrails whose escalation-to-deny is itself trust-gated on
`enforcement_mode == "enforce"`, so an observe agent can never receive them
in the first place (see "Composition with the other guardrails" below):

- `signature_match` (signature enforce escalation,
  `src/terminus/signature/matcher.py`; gated at
  `src/terminus/interceptor/router.py:233-234`)
- `velocity_anomaly` (velocity enforce escalation, gated at
  `src/terminus/interceptor/router.py:273-278`)

The allowlist is a deliberate construction, not an oversight: any deny
`reason_code` added to the engine in the future is floor by default (denied
in observe) until someone consciously adds it to `OBSERVE_SOFTENABLE`. A new
deny reason can never accidentally become softenable.

`wrong_tool` never reaches the transform at all. It is decided in
`src/terminus/mcp/decider.py:63-82`, before `policy_engine.evaluate()` runs,
so there is no `PolicyDecision` for `soften_if_observing` to see yet; it is
floor by construction, not by allowlist membership.

`soften_if_observing` (`src/terminus/policy/graduated.py:46-68`) is the one
function that performs the conversion. On a softenable deny for an observing
agent, it returns a new `PolicyDecision` with `action="allow"`,
`reason_code="observe_softened"`, and `reason` prefixed `"[observe] would
deny: <original reason>"`, plus `would_deny=True` and the original
`reason_code`. On anything else (an allow, a non-observing agent, or a floor
code) it returns the decision unchanged with `would_deny=False`.

## The identity rule (F9 lesson, inverted)

Graduated autonomy keys the softer posture on the same unspoofable-identity
principle the F9 velocity guardrail already established: **a spoofed
identity can weaken enforcement**, so posture must key on identity the
requester cannot choose for themselves.

- **HTTP `/intercept`:** observe is honored only when `agent_authenticated`
  is `True`, meaning a JWT was presented and its `sub` verified against the
  registry (`src/terminus/interceptor/router.py:163-168, 201-206`). Legacy
  unauthenticated traffic that self-asserts `payload.agent_id` always
  resolves to `enforce`, even if that same id has `trust_level: observe` in
  the registry: `resolve_enforcement_mode` checks `agent_authenticated`
  before it ever calls `registry.trust_of()` (`graduated.py:41-43`). An
  attacker cannot claim someone else's observe-mode identity to get a
  softer posture.
  - **Practical consequence: run with `TERMINUS_REQUIRE_AUTH=true`.**
    Graduated autonomy only pays off for authenticated agents; with
    `REQUIRE_AUTH=false` (the default), any agent that never sends a JWT
    is, correctly, always enforced, but that also means an agent you meant
    to onboard in observe mode gets no benefit until it authenticates. See
    [docs/capabilities/agent-identity.md](agent-identity.md) for enabling
    JWT auth.
- **MCP:** the agent identity is `TERMINUS_MCP_AGENT_ID`, an operator-set
  config value validated against the registry at server startup
  (`resolve_agent_id`, `src/terminus/mcp/server.py:29-36`), never anything
  the client can assert per-call. `ToolService._handle()` resolves trust
  from the live registry snapshot on every call with
  `agent_authenticated=True` fixed by construction
  (`src/terminus/mcp/server.py:69-78`), so a promotion applies to the next
  call without a server restart, but the identity itself is boot-bound and
  unspoofable by the MCP client.

## Placement in the pipeline

The transform runs in exactly two places, both immediately after
`policy_engine.evaluate()` and before every downstream guardrail,
remediation, metrics, and audit call:

- **HTTP:** `src/terminus/interceptor/router.py:196-210`, between the
  policy decision and the signature/velocity guardrails.
- **MCP:** inside `src/terminus/mcp/decider.py::decide()`
  (`decider.py:84-85`), between `evaluate()` and the
  Allowed/Denied/NeedsApproval branching. It has to live inside `decide()`
  rather than in `server.py` so `ExecutionGrant` stays minted in exactly one
  place (`decide()`), preserving the MCP no-bypass structural test
  (`tests/mcp/test_no_bypass.py`; see
  [docs/capabilities/mcp-enforcement-point.md](mcp-enforcement-point.md)).

`policy_engine.evaluate()` itself is untouched by this feature: it has no
concept of trust and never will.

## Composition with the other guardrails

Per-agent trust gates ENFORCEMENT of the other guardrails, never their
detection. Each guardrail keeps recording telemetry for every agent
regardless of trust; only the escalation-to-deny step checks trust.

- **Velocity** (`src/terminus/interceptor/router.py:273-278`): an anomaly
  always gets flagged (`velocity_anomaly` in `risk_reasons`, the
  `terminus_velocity_anomaly_total` metric), but it only escalates to a
  deny when `velocity_enforce_enabled AND agent_authenticated AND decision
  allow AND enforcement_mode == "enforce"`. An observe agent's anomalies are
  recorded with `enforced=false` and never denied.
- **Signature enforcement** (`src/terminus/interceptor/router.py:233-234`):
  `evaluate_match(..., enforce_enabled=settings.signature_enforce_enabled
  and enforcement_mode == "enforce")`. The per-agent trust flag is
  necessary but not sufficient, exactly mirroring how
  `signature_enforce_enabled` alone was never sufficient before this
  feature: an observe agent's signature match is recorded but never
  escalates an allow to a deny.
- **Emit-only signature behavior** (the default,
  `signatures_enabled`/telemetry) is unaffected either way: it does not
  check trust at all, because it never changes a decision.

This keeps every guardrail's own metrics honest: an escalated deny is never
retroactively relabeled, and an observe agent's guardrail telemetry is
exactly as informative as an enforce agent's, just never load-bearing.

## Break-glass composition (MCP)

Observe softens a POLICY deny; it never touches the human-approval gate. A
softened decision still flows through the same risk check every other allow
does (`src/terminus/mcp/decider.py:110-125`): if the (now-allowed) write's
operation is `INSERT`/`UPDATE`/`DELETE`/`MERGE` and its risk score is at or
above `TERMINUS_MCP_APPROVAL_RISK_THRESHOLD`, it returns `NeedsApproval` and
waits for a human exactly as an ordinarily-allowed high-risk write would. An
observe-mode agent gets evidence instead of a policy block on a softenable
code, not a free pass past break-glass. Floor denies (e.g. `nested_write`,
`injection_function`) never reach this point at all and never mint a grant,
observe or not.

## Promotion runbook

1. Edit `agents.yaml`, add or change `trust_level` on the agent's entry:

   ```yaml
   agents:
     - id: onboarding_agent_9
       description: "New ETL agent, being evaluated"
       trust_level: enforce          # was: observe
       trust_changed_by: "will@example.com"      # optional
       trust_change_reason: "two weeks clean would_deny evidence"  # optional
   ```

   `trust_changed_by` and `trust_change_reason` are optional provenance
   fields on `AgentEntry` (`src/terminus/auth/registry.py`). Omit either and
   the signed audit event records the literal string `"unspecified: see git
   history"` in its place (`_UNSPECIFIED_PROVENANCE`,
   `src/terminus/audit/audit_logger.py`) rather than a null: they are
   SIGNED fields, so they must always have a stable, present value even
   when the human context lives only in the commit that changed the file.

2. **Reload.** With `TERMINUS_CONFIG_RELOAD_INTERVAL` set to a positive
   number of seconds (a GitOps deployment where a sidecar keeps the files
   current), the change is picked up automatically on the next poll
   (`run_config_poll_loop`, `src/terminus/config/governance.py:214-220`);
   the default `0` loads once at startup only. See
   [docs/configuration.md](../configuration.md) section 1 for the setting.
   No restart is required either way, the registry is part of the same
   atomically-swapped `GovernanceSnapshot` as the policy engine and
   whitelist.

3. **Verify the chained event.** A successful reload that changed any
   agent's effective trust emits one signed `terminus_trust_level_change`
   event per changed agent (`src/terminus/config/governance.py:187-203`,
   `_trust_changes`, `governance.py:108-128`). Confirm it landed and
   verifies:

   ```python
   from terminus.audit.verify import verify_audit_chain

   result = verify_audit_chain(open("audit.log"), hmac_key, require_genesis=True)
   assert result.ok, result.failures
   ```

   The event carries `agent_id`, `previous_trust_level`, `new_trust_level`,
   `governance_version` (the reload's config hash, truncated),
   `trust_changed_by`, `trust_change_reason`, `sequence`, and
   `schema_version`; see [docs/capabilities/audit.md](audit.md) for the
   full field reference and how it shares the chain with decision events.

   The diff itself is computed over EFFECTIVE trust
   (`AgentRegistry.trust_of`, which folds in `status`), not the raw
   `trust_level` field: a `status` flip alone can change what actually gets
   enforced, so it emits its own signed event even when `trust_level` never
   changes.

**A brand-new agent added directly with `trust_level: observe`** also emits
a chained event, but only when its EFFECTIVE trust ends up `observe`:
`_trust_changes` treats "not present in the old registry" plus "new
effective trust is observe" (`new.trust_of(agent.id)`) as a change from
`previous_trust_level: "unregistered"` (`governance.py:108-140`), because
unregistered otherwise means enforce-by-default and observe is the posture
that needs an audit trail. A brand-new agent added as `enforce`, with
`trust_level` omitted, or added `status: disabled` (whose effective trust is
always `enforce` regardless of the stored `trust_level`) emits nothing: none
of those change anything from today's default.

**Removing an agent from the registry emits nothing.** `_trust_changes`
only diffs agents present in the NEW registry (`governance.py:108-140`); a
removed agent is not iterated at all. This is intentional, not a gap: a
removed agent's tokens are rejected by auth regardless (401, unknown
`sub`), which is strictly stricter than any trust level, so there is no
promotion/demotion event to record.

**Disabling an agent in place (`status: disabled`, entry kept) is NOT the
same as removing it, and can emit an event.** Because `trust_of` forces
`enforce` whenever `status != "active"`, disabling an active `observe`
agent is a genuine enforcement tightening -- `observe` -> `enforce` -- even
though `trust_level` itself is untouched, and it is recorded exactly like
any other effective-trust change. Symmetrically, reactivating a
`disabled`/`observe` agent back to `active` (again, `trust_level`
unchanged) reads as `enforce` -> `observe`: the posture just weakened, so it
must be visible in the same chained event, not silent because the diff once
only looked at `trust_level`.

**Boot-time initial load emits nothing either.** The trust-change event
only fires from a runtime `reload_now()` diff against the PRIOR snapshot;
the first snapshot built at process construction
(`GovernanceConfigManager.__init__`, `governance.py:139-140`) is the genesis
baseline, not a change from anything.

## The evidence workflow

Before promoting an agent, look at what it WOULD have been denied:

- **Metric:** `terminus_would_deny_total{reason_code, operation}`
  (`src/terminus/observability/metrics.py:80-89`), incremented once per
  softened request, labeled by the ORIGINAL deny `reason_code` (e.g.
  `schema_whitelist`, `policy_rule`), never the synthetic
  `observe_softened` label. This is the promotion-evidence dashboard: break
  it down by `reason_code` to see exactly what enforce would start
  blocking.
- **Audit trail:** every softened decision is a normal
  `terminus_intercept_decision` (or MCP-tool) event with `decision="allow"`
  (it executed), `reason_code="observe_softened"`, `would_deny=true`, and
  `would_deny_reason_code=<original code>` (schema v3; see
  [docs/capabilities/audit.md](audit.md)). The chain never records a deny
  for a statement that actually ran, and a dashboard built on `reason_code`
  never counts phantom denies under the original codes, the truth is
  `allow` + the `would_deny_*` evidence fields, not a relabeled deny. On a
  softened allow, `policy_id` still names the rule that WOULD have denied
  the statement (the evidence), not a rule that allowed it, since
  `policy_engine.evaluate()` itself never produced an allow here.
- **Signature evidence, when `signatures_enabled`:** a would-deny event
  still emits a name-free signature record even though the decision itself
  is an allow (`src/terminus/interceptor/router.py:342-354`), gated the
  same as every other signature emission by the `signatures_enabled` master
  switch: with it off, a softened event produces zero signature telemetry,
  matching the switch's normal on/off contract rather than sneaking
  evidence out through a side door.

## The master switch

`TERMINUS_GRADUATED_AUTONOMY_ENABLED` (default `false`) is documented in
full in [docs/configuration.md](../configuration.md) section 11. Off,
`trust_level` is ignored everywhere and behavior is byte-for-byte
today's, including the v3 audit defaults (`enforcement_mode="enforce"`,
`would_deny=false`, `would_deny_reason_code=null` on every event). This is a
tested regression guarantee (spec test 1), not just a design intention.

## Non-goals (v1)

- No operator UI or API for promotion; GitOps edit + reload is the only
  mechanism.
- No per-rule or per-table observe granularity, only per-agent.
- No automatic promotion (no thresholds, no timers); a human decides.
- No new persistent store; the known multi-worker chain-fragmentation
  limitation (H1 in GAPS.md, "Stateful controls silently fragment under more
  than one worker") is unchanged by this feature.
- No backfill: v1 and v2 audit lines verify forever alongside v3 via the
  verifier's per-version field-set selection.
