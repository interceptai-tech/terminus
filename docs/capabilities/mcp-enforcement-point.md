# MCP Enforcement Point

A reference implementation that puts Terminus in front of an agent's database
access as an unbypassable gate, rather than an API an agent chooses to call.
Configuration is in [docs/configuration.md](../configuration.md); the security
model is in SECURITY.md; integration is in
[docs/integration.md](../integration.md).

## What it does

The HTTP sidecar (`/intercept`) is advisory: it tells an agent whether a
statement is allowed, but the agent still holds the database credentials and
still has to choose to obey the answer. The MCP enforcement point removes that
choice. It exposes a Model Context Protocol (MCP) server with exactly two
tools, `query` and `execute`. The agent never receives a database connection
string, and the only way for it to touch the database at all is through those
two tools. Every call is decided by the same parser and policy engine as the
HTTP sidecar, in-process, before anything runs.

Entry point: `python -m terminus.mcp` (`src/terminus/mcp/__main__.py`). Off by
default; the master switch is `TERMINUS_MCP_ENABLED`.

The stdio entrypoint logs to stderr, not stdout (`configure_logging(stream=
sys.stderr)` in `__main__.py`): stdout is reserved for MCP protocol framing, so
anything written there would corrupt the transport. This is also where the
audit chain (see Audit binding below) actually lands when this server runs as
a subprocess, so a client that wants the audit trail needs to capture the
subprocess's stderr, not its stdout.

## PDP / PEP framing (NIST SP 800-207)

NIST SP 800-207 (Zero Trust Architecture) separates a Policy Decision Point
(PDP), which decides, from a Policy Enforcement Point (PEP), which is the only
component with the authority and the means to act on that decision. Terminus's
existing decision engine (`parser.sql_parser.parse_sql` +
`policy.policy_engine.PolicyEngine`) is the PDP: unchanged, reused as-is, it
never touches a database and never executes anything. The MCP server is the
PEP: it is the sole component that holds database credentials
(`TERMINUS_MCP_POSTGRES_DSN`) and the sole component capable of issuing SQL, so
a PDP decision is meaningless to bypass, there is no other path to the
database for the PEP to guard.

`src/terminus/mcp/decider.py :: decide()` is the boundary between the two: it
calls the PDP (`parse_sql` then `PolicyEngine.evaluate()`) and translates the
result into one of three outcomes (`src/terminus/mcp/grants.py`):

- **`Allowed(grant)`**: a low-risk allow. Execute immediately.
- **`Denied(reason, reason_code, remediation)`**: never executes. `remediation`
  carries a `suggested_sql` field, a ready-to-run, already-revalidated rewrite,
  whenever the policy engine's `suggest_rewrite` can produce one (the same
  field the HTTP sidecar returns; see `docs/integration.md`), so an MCP client
  can retry with it directly instead of round-tripping the fix through a model.
- **`NeedsApproval(grant, request_id, reason)`**: an allowed write held for a
  human decision before it executes (see Break-glass below).

## The two tools

`query` runs read-only `SELECT`s; `execute` runs writes. `decide()` enforces
the split for valid, single statements: a `SELECT` sent to `execute`, or a
non-`SELECT` sent to `query`, is denied with `reason_code=wrong_tool`
(`src/terminus/mcp/decider.py:52-65`). Invalid SQL and multi-statement input
skip that check and fall straight through to the policy engine, which denies
them with the accurate, existing reason codes (`invalid_sql`, `oversize_sql`,
`multi_statement`) and real remediation, rather than the misleading
`wrong_tool` label.

`normalize_dialect` is pinned to the trusted, operator-configured
`TERMINUS_SQL_DIALECT` exactly as it is on the HTTP path (F10c); the MCP tools
take only raw SQL text, so there is no attacker-controlled dialect field to
guard against here in the first place.

## Credential isolation and the no-bypass guarantee

Two structural properties, not just code review, back the claim that a
statement cannot reach the database without a PDP decision:

- **`Executor` is the sole SQL runner and the sole holder of database
  credentials** (`src/terminus/mcp/executor.py`). It is constructed once, in
  `build_server()`, from `TERMINUS_MCP_POSTGRES_DSN`; nothing else in the
  process opens a database connection.
- **`Executor.run()` accepts only an `ExecutionGrant`.** It does an `isinstance`
  check and raises `TypeError` on anything else, including a raw SQL string,
  even if a caller bypasses the type hints (`src/terminus/mcp/executor.py:43-44`).
- **`ExecutionGrant` is minted in exactly one place: `decider.decide()`, on an
  allow.** No other module in `terminus.mcp` constructs one. This is not just
  a convention, `tests/mcp/test_no_bypass.py` asserts it structurally by
  scanning every module in the package's source for the constructor call and
  failing if any module other than `grants`, `decider`, `approvals`, or
  `server` contains it.

Together, this means there is no callable path from a deny, or from an
unresolved approval, to execution: the only way to obtain an `ExecutionGrant`
is to have already been allowed (or approved) by the policy engine.

**Deployment topology** is what makes this unbypassable in practice, not just
in code: the agent process must hold no database credentials and have no
network route to the database at all, only to the MCP server. The MCP server
holds `TERMINUS_MCP_POSTGRES_DSN` and sits on the only network path with
access to the database. If the agent's environment is not network-segmented
this way, the credential-isolation guarantee is cosmetic, the agent could
simply open its own connection alongside the MCP tool calls. One server
instance serves one agent identity (`resolve_agent_id()` validates
`TERMINUS_MCP_AGENT_ID` against the registry at startup and raises if it is
missing or not active), so a multi-agent deployment runs one MCP server
process per agent.

## Human-approval break-glass

A write is held for approval, not executed immediately, when its parsed
operation is one of `INSERT`/`UPDATE`/`DELETE`/`MERGE` and its risk score is at
or above `TERMINUS_MCP_APPROVAL_RISK_THRESHOLD` (default `0.8`, catches a
`DELETE` and a `WHERE`-less `UPDATE`; see docs/configuration.md)
(`src/terminus/mcp/decider.py:78-89`). This is policy- and risk-driven, reusing
the same risk score the HTTP sidecar computes; it is never a hardcoded list of
"dangerous" operations.

The flow (`src/terminus/mcp/server.py :: ToolService._handle()`):

1. The grant is submitted to the in-process `ApprovalBroker`
   (`src/terminus/mcp/approvals.py`), which holds it under the request id.
2. The decision (`pending_approval`) is written to the audit chain.
3. The tool call blocks on `broker.wait(request_id, timeout=TERMINUS_MCP_APPROVAL_TIMEOUT_SECONDS)`
   (default 300s).
4. An operator resolves it by calling `broker.approve(request_id)` or
   `broker.deny(request_id)`.

**Be honest about the MVP:** there is no operator-facing API or CLI in this
reference implementation. Approval is a programmatic, in-process call against
the single running `ApprovalBroker` instance, an operator (or an internal tool
built on top of it) needs code-level access to that instance in the same
process to call `approve`/`deny`. A dedicated operator surface (an admin
endpoint or CLI that can reach a running server's broker) is a documented
fast-follow, not present here.

Whatever the operator does, the broker keeps the outcome fail-closed:

- **First decision wins.** `_resolve()` is a compare-and-swap: once a request
  has a result, a second `approve`/`deny` call returns `False` and cannot
  change it. A `deny` can never be flipped back to an approve by a later,
  possibly mistaken or racing, call (`src/terminus/mcp/approvals.py:62-74`).
- **Timeout, deny, and expiry all release no grant.** Only `approve` yields
  the held `ExecutionGrant` back to the waiter; every other outcome
  (`DENIED`, `EXPIRED`) returns `None` in its place, and `ToolService` reports
  `approval_denied` or `approval_expired` without executing anything.
- **Single-instance, single-waiter-per-request-id.** The broker is in-memory
  and per-process; it does not survive a restart, and it assumes one `wait()`
  call per `request_id` and unique `request_id`s per `submit()`. Both are
  documented MVP assumptions in the module docstring
  (`src/terminus/mcp/approvals.py:36-49`); violating them still cannot leak a
  grant without an explicit approve, it can only desync bookkeeping (an
  orphaned second waiter, or a replaced pending entry).

## Audit binding

Every tool call, allow, deny, pending-approval, approved, denied-by-approval,
or expired, is written into the existing tamper-evident HMAC chain
(`terminus.audit.audit_logger.AuditLogger.log_decision`, the same signed record
the HTTP sidecar uses; see [docs/capabilities/audit.md](audit.md)). As of audit
schema v2, `mcp_tool` (`"query"` or `"execute"`) and `mcp_approval_status` are
passed to `log_decision` as first-class, signed keyword arguments through
`record_tool_decision` (`src/terminus/mcp/audit.py`), not through `metadata`.

**Fail-closed audit-before-execute.** `ToolService` writes the decision to the
audit chain *before* calling `Executor.run()`, on both the immediate-allow path
and the approved-after-review path (`src/terminus/mcp/server.py:112-132`). If
audit logging itself fails, the tool call returns `reason_code=audit_error`
and never executes: no statement runs without its decision already durably
recorded. The audit event always records the decision, not the execution
outcome, an audited "approved, running" write that then hits a database error
still shows as approved in the chain; the execution failure is logged
separately (exception class and request id only, per the repo's no-raw-error
rule) and returned to the caller as a generic `execution_error`, never a raw
driver exception.

The parse and decision recorded are the exact same ones `decider.decide()`
produced for the call, threaded through the outcome (`Allowed` / `Denied` /
`NeedsApproval` in `src/terminus/mcp/grants.py`) rather than re-parsed and
re-evaluated at audit time. This guarantees the signed record can never
disagree with what the client was actually told, including for the
wrong-tool short-circuit (a SELECT sent to `execute`, or a write sent to
`query`), which denies before policy evaluation ever runs and carries a
synthetic deny decision (`reason_code=wrong_tool`) built for that purpose.

**Tool identity and approval outcome are first-class signed fields.** As of
audit schema v2, `mcp_tool` and `mcp_approval_status` are part of
`AUDIT_SIGNED_FIELDS` (see docs/capabilities/audit.md), covered by the HMAC the
same way `operation` or `reason_code` are, so an audit line for an MCP call
shows exactly which tool ran and how any approval resolved, and tampering with
either value breaks the event's signature like any other signed field. Events
written before schema v2 predate this promotion: they carry only
`metadata_keys` for MCP context, the key names, not `mcp_tool` or
`mcp_approval_status` themselves, so a consumer reading older lines must not
assume the v2 fields are present.

## Availability trade-off: fail-closed, no degraded mode

The MCP enforcement point has no fail-open path anywhere in its decision or
execution flow. Contrast this with the HTTP sidecar's rate limiter, which
fails open by design (SECURITY.md) so a Redis outage does not block SQL
validation. Nothing in the MCP path works that way:

- Boot guards (`assert_production_secrets`, `assert_known_dialect`,
  `resolve_agent_id`) fail loudly and refuse to start rather than run with a
  default secret or an unregistered agent identity (`src/terminus/mcp/__main__.py`,
  `src/terminus/mcp/server.py:29-36`).
- An unreachable database, a failed audit write, a broker timeout, or a parse
  error all resolve to a deny or an error response. None of them fall back to
  running the statement anyway.
- There is deliberately no "degraded mode" switch. If the MCP server (or its
  dependencies) is unhealthy, the correct behavior is that agent traffic stops,
  not that it runs unchecked.

Availability is bought the same way any fail-closed gate buys availability:
**redundant replicas**, not a bypass. Run multiple MCP server processes (one
per agent identity, per the topology above) behind the same network
segmentation, so a single process failure is a capacity problem handled by
routing around it, never a reason to let an agent talk to the database
directly.

## Reference client: the live write dogfood

`dogfood/README.md` is a reference MCP client for this enforcement point: a
real LangGraph agent, backed by a real model, making real writes against a
throwaway Postgres database through exactly the `query`/`execute` tools
described above, with an allowed write, a blocked destructive write, a
self-corrected wildcard query (using the `suggested_sql` above), and a
verified audit chain, checked against actual database rows and the signed
audit log rather than the agent's own account of what happened. Run it with
`make dogfood` (needs Docker and `ANTHROPIC_API_KEY`) or `make dogfood-smoke`
(wiring check, no model calls). It is a manual gate, not part of CI.

## Configuration quick reference

`TERMINUS_MCP_ENABLED`, `TERMINUS_MCP_AGENT_ID`, `TERMINUS_MCP_POSTGRES_DSN`,
`TERMINUS_MCP_APPROVAL_RISK_THRESHOLD` (default `0.8`), and
`TERMINUS_MCP_APPROVAL_TIMEOUT_SECONDS` (default `300`) are documented in full,
with defaults and interactions, in
[docs/configuration.md](../configuration.md).

## Known deferrals (not gaps, scoped out of this reference implementation)

- An operator-facing approval surface (admin API or CLI) beyond direct
  in-process `ApprovalBroker` calls.
- A shared-store `ApprovalBroker` for multi-replica or crash-surviving
  approvals (current broker is in-memory, single-process).
- Per-session JWT identity over MCP transport auth (current model is one
  server process per agent identity, validated at startup).
- Capability manifests, intent-level tools, attestation certificates, a
  graduated-autonomy state machine, multi-database support, and a remote
  decision plane are all out of scope for this reference PEP.
