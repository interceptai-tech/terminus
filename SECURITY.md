# Security Architecture – Terminus

## Core Principles

- **Default Deny**: Everything is blocked unless explicitly allowed.
- **Schema Whitelisting**: Only tables listed in `examples/schema_whitelist.yaml` are permitted. Any reference to an unknown table triggers an immediate deny.
- **SQL Smuggling Defense**: The parser inspects the `sqlglot` AST for smuggling signals. Detection is AST-based, not substring matching, so a type name like `varchar(255)` is never confused with the `char()` function.
  - **Injection / time-based functions** (`pg_sleep`, `sleep`, `benchmark`, `waitfor`, `xp_cmdshell`, `pg_read_file`, ...) are matched by function-node name and, by default, **denied on the allow path** (`reason_code=injection_function`) even if a policy rule would otherwise allow the query. This is a core, fail-closed control governed by `TERMINUS_ENFORCE_INJECTION_BLOCK` (default `true`); set it `false` to observe-only during migration (the signal is still surfaced in `risk_reasons` and metrics but never changes the decision).
  - **Writable CTEs (nested writes)**: a statement is classified by its top-level operation only, so `WITH d AS (DELETE FROM public.users WHERE id = 1 RETURNING id) SELECT 1` is classified as SELECT, and the operation-based policy rules (like the destructive-operation deny) would otherwise never see the nested DELETE and it would be allowed to run. A fail-closed gate inspects every CTE body for a data-modifying operation (INSERT, UPDATE, DELETE, MERGE) and denies the statement outright (`reason_code=nested_write`) before any policy rule runs. Detection is by CTE body, so a normal top-level MERGE, whose WHEN arms are internally INSERT/UPDATE, is not affected. Unlike injection detection, this has no config toggle: under a default-deny posture a smuggled write has no benign reading. This is a deliberate behavior change: a legitimately-intended writable CTE (for example `WITH moved AS (DELETE FROM orders ... RETURNING *) INSERT INTO archive SELECT * FROM moved`) is also denied; submit the write as its own top-level statement so policy can evaluate it.
  - **Comment obfuscation** (`--`, `/* */`, nested comments), **hidden subqueries**, and **set operations** (`UNION`, `INTERSECT`, `EXCEPT`) are detected and raise the risk score but remain **advisory** (they do not auto-deny): the schema whitelist already contains that exfiltration vector, and enforcing them would false-positive on legitimate analytics.
  - A query that cannot be parsed is denied outright (`invalid_sql`).
- **Bounded, Fail-Closed Parsing**: The parser is cost-bounded and never crashes the request. Input longer than `TERMINUS_MAX_SQL_LENGTH` (default 16 KiB) is denied before parsing (`reason_code=oversize_sql`); an unknown dialect, pathological nesting, or any parser error is denied (`reason_code=invalid_sql`), never a 500. Parsing runs off the event loop, so one large query cannot block the sidecar.
- **Rate Limiting**: Per-agent rate limiting (default 10 req/min) on `/intercept`, enforced by `fastapi-limiter` + Redis. Keyed on the `X-Agent-ID` header (falling back to client IP). **Fails open**: if Redis is unreachable the limiter is skipped (logged as `rate_limit_skipped`) so SQL validation still runs rather than blocking all traffic. Rate limiting is a guardrail, not the core circuit breaker.
- **Tamper-Proof Audit Logs**: Every audit event is cryptographically signed with HMAC-SHA256 using a secret key. Logs form a chained sequence (each record includes the previous signature). This provides strong forensic integrity even if the host is compromised.
- **No Secrets in Logs**: Raw SQL is never logged; only `sql_sha256` is recorded, a keyed HMAC-SHA256 digest of the SQL computed with the deployment's secret `TERMINUS_AUDIT_HMAC_KEY`, not a bare SHA-256 hash. Its confidentiality depends on that secret: without it, the digest is not reversible or brute-forceable, even against a low-entropy literal like an SSN or email address. In `development` the shipped default key is public, so dev-mode digests are still guessable; production and staging refuse to boot on the default (see Configuration below). Connection URLs are scrubbed of any embedded `user:password` before being logged (`_safe_redis_target`), so credentials never reach a log aggregator.

## Whitelisting Behavior

The whitelist check happens **before** any policy rule evaluation in
`PolicyEngine.evaluate()` (after the invalid-SQL and multi-statement guards).
This creates a strong "implicit deny" model: the whitelist decides *which* tables
are reachable at all, and the policy rules then decide *what* may be done to them.

```yaml
# examples/schema_whitelist.yaml
version: "1.0"
enabled: true            # set false to disable enforcement (rules still run)
tables:
  - public.users
  - public.orders
  - analytics.*          # shell-style globs, matched case-insensitively
remediation_message: >-
  Query references a table that is not on the Terminus schema whitelist...
```

Any referenced table that does not match an entry → **immediate deny**,
regardless of allow rules elsewhere. The denial carries `reason_code`
`schema_whitelist` (used for the `terminus_requests_total` metric) and a
`policy_id` of `schema_whitelist` in the audit log. Table names are compared in
the parser's normalized `schema.table` form. A query that references no tables
(e.g. `SELECT 1`) passes the whitelist and is then judged by the policy rules.

### Column Allowlists

A table entry may opt into column-level restriction by listing `columns`:

```yaml
tables:
  - public.users:
      columns: [id, name, email]   # only these columns may be referenced
  - public.orders                  # no list: all columns allowed
```

Rules:
- Default-deny on the listed columns: any reference to a column not on the list is denied (`reason_code` `column_whitelist`).
- Column identifier matching is quote-aware, per standard SQL/Postgres semantics: an unquoted identifier folds to lowercase before matching (the default/Postgres `NormalizationStrategy.LOWERCASE`), the same as the lowercased allowlist, but a quoted identifier keeps its exact case and is not folded. So a quoted case-variant of an allowlisted column, e.g. `"EMAIL"` where the allowlist has `email`, no longer matches and is denied (`reason_code` `column_whitelist`) instead of being silently treated as the allowlisted column. This holds everywhere a column is checked: SELECT projections, `WHERE`/`GROUP BY`/`HAVING`, `ORDER BY` (including a term that only appears to reference a select-list alias but differs from it in case), INSERT target lists, and UPDATE/MERGE SET targets. The change is strictly fail-closed: it can only remove previously-allowed queries, never add new ones. Identifier matching is dialect-aware (F10c, resolved): it follows the deployment's configured `TERMINUS_SQL_DIALECT` (default empty, meaning generic/Postgres `LOWERCASE`) via sqlglot's `normalize_identifiers`, and that same dialect is applied when the whitelist and policy config are loaded, so a Snowflake deployment (which unquoted-folds to UPPERCASE) or any other non-lowercase dialect matches query identifiers against the config correctly instead of being blind to the dialect's case rules. Residual: whitelist config identifiers are still folded as unquoted, so a genuinely quoted mixed-case column cannot be expressed in the whitelist; that is a fail-closed over-deny, not a bypass.
- Applies to all column references, reads and writes: `UPDATE users SET password_hash = ...` is blocked, and so is `INSERT INTO users (id, name, password_hash) VALUES (...)`. INSERT target column lists are checked against the allowlist exactly like UPDATE SET (`reason_code=column_whitelist`).
- An INSERT with no column list (`INSERT INTO users VALUES (...)` or `INSERT INTO users DEFAULT VALUES`) on a column-restricted table writes every column implicitly and cannot be proven within the allowed set without DB schema introspection, so it is denied the same as a bare `*` (`reason_code=column_whitelist`).
- Wildcards (`*`, `t.*`) are denied on a column-restricted table: a wildcard cannot be proven to stay within the allowed set without DB schema introspection, which Terminus does not do. `COUNT(*)` and other aggregate stars are allowed because they leak no column values.
- In a join, qualified columns (`u.name`) are attributed to their table and checked. An unqualified column alongside a column-restricted table is ambiguous and fails closed (denied, logged `column_attribution_ambiguous`); the agent is told to qualify its columns.
- A `SELECT` output alias never hides a base column. A bare column in `WHERE`, `GROUP BY`, or `HAVING` is always checked against the allowlist even when its name matches a select-list alias: aliases are not visible in `WHERE`/`JOIN ... ON`, and PostgreSQL resolves an ambiguous `GROUP BY`/`HAVING` name to the base column. So `SELECT id AS ssn FROM users WHERE ssn = '...'` is denied (it reads the restricted `ssn`), not allowed via the aliased projection. Only a genuine `ORDER BY` reference to an output alias is treated as an alias rather than a base-column access.
- Globs (`analytics.*`) are always all-columns. A glob entry that carries a `columns` list logs `schema_whitelist_glob_columns_ignored` and the list is ignored.

Limitations: enforcement depends on a faithful sqlglot parse. A parse failure is not a bypass (invalid SQL is denied outright), but a silent misparse could under-enforce a column rule; the fail-closed-on-ambiguity rule bounds this. Terminus does not read the database schema, so a column present in the table but omitted from an explicit INSERT column list is not defaulted or schema-validated; the no-column-list deny above is what covers a write to every column. Fixed, tracked as F10b: table identifier canonicalization is now quote-aware too, the same treatment as columns above. An unquoted table name, including its schema/catalog qualifiers, table aliases, and qualified-column table qualifiers, still folds to lowercase, but a quoted table name keeps its exact case. So a quoted case-variant of a whitelisted table, e.g. `SELECT id FROM "public"."USERS"` where the whitelist has `public.users`, no longer matches and is denied (`reason_code=schema_whitelist`) instead of being silently treated as the whitelisted table. The change is strictly fail-closed under the default/Postgres `LOWERCASE` model; the dialect matching described for columns above applies identically to tables: matching follows `TERMINUS_SQL_DIALECT` for both query identifiers and the whitelist config, so a non-lowercase-normalizing dialect like Snowflake is matched correctly rather than being dialect-blind (F10c, resolved). Residual: whitelist config patterns are still case-folded as unquoted, so a genuinely quoted mixed-case table, a real object literally named `"Orders"`, cannot be expressed in the whitelist at all; the folded config pattern never matches its case-preserved canonical name, which is a permanent but fail-closed over-deny, not a bypass.

### Suggested Rewrites

When a query is denied for using a wildcard (`*`) on a column-restricted table,
the deny response may include a `suggested_sql`: a runnable rewrite that
enumerates the allowed columns (for example `SELECT * FROM users` becomes
`SELECT id, name FROM users`). This lets an agent self-correct on retry.

The rewrite is never trusted blindly. Terminus re-evaluates the candidate
through the full pipeline (table whitelist, column whitelist, policy rules) for
the same agent and attaches it only if it would be allowed. If the rewrite would
still be denied (for example the agent has no allow rule for the table), no
`suggested_sql` is returned. The rewrite appears only in the JSON response body,
never in the `X-Terminus-Remediation` header. The audit event records a
`rewrite_suggested` boolean, not the rewrite text.

### Remediation header sanitization

The `X-Terminus-Remediation` header value interpolates attacker-influenced SQL identifiers and is scrubbed of all C0 control characters and DEL (not just newlines) before emission, preventing response-splitting attacks that would otherwise turn a valid 403 into a 500 (GAPS M4).

### Agent Identity (JWT)

Agents authenticate with an HS256 JSON Web Token in `Authorization: Bearer <jwt>`,
signed with `TERMINUS_JWT_SECRET`. The trusted `agent_id` is the verified `sub`
claim; the `X-Agent-ID` header and any body `agent_id` are then ignored for
identity, policy, rate limiting, and logging. The `sub` must match a registered,
active agent in `agents.yaml` (an unknown or disabled `sub` is rejected even with
a valid signature, that is how an agent is revoked without rotating the secret).

Enforcement (`TERMINUS_REQUIRE_AUTH`, default false):

| Case | require_auth=false (default) | require_auth=true |
|------|------------------------------|-------------------|
| Valid JWT, registered sub | use sub | use sub |
| No Bearer token | legacy self-asserted (warned + counted) | 401 |
| Malformed / expired / bad signature | 401 | 401 |
| Unknown / disabled sub | 401 | 401 |

Invalid tokens always return 401, even in permissive mode; only the completely
absent-token case is governed by the flag, so deployments can migrate safely.
Verification pins the algorithm to HS256 (an `alg=none` or algorithm-confusion
token is rejected). Tokens are minted out of band by the operator CLI, Terminus
never mints at runtime:

    python -m terminus.auth issue --agent analytics_agent_42 --expires-days 30

Auth outcomes are exported as `terminus_auth_events_total{result=verified|rejected|legacy}`.

### JWT expiry and minted-lifetime cap

Two additive, fail-closed checks in `verify_token`:

- **`TERMINUS_JWT_REQUIRE_EXP`** (auto `true` in staging/production, `false` in
  development): makes the `exp` claim mandatory. A present `exp` is always
  checked with zero clock leeway regardless of this flag; it only governs
  whether `exp` may be absent.
- **`TERMINUS_JWT_MAX_LIFETIME_SECONDS`** (default `0`, disabled): when `> 0`,
  caps the *minted* lifetime (`exp - iat`), and makes both `exp` and `iat`
  mandatory integer claims (rejecting non-int and bool values, since `bool` is
  an `int` subclass in Python), regardless of `TERMINUS_JWT_REQUIRE_EXP`. A
  missing `iat`, a non-positive lifetime (`exp <= iat`), or a lifetime over the
  cap is rejected.

Failure taxonomy is deliberately flat: every expiry, lifetime, or malformed-claim
failure reports `invalid_token`, the same bucket as a bad signature or wrong
algorithm, so a probing attacker cannot distinguish "expired" from "too long-lived"
from "forged." An unknown or disabled `sub` still reports `unknown_agent`
separately, since that failure mode is about registry state, not the token
itself.

**Rollout hazard.** Enabling `TERMINUS_JWT_REQUIRE_EXP` (the default once this
release is deployed to staging/production) immediately invalidates any
pre-existing token minted with `--no-expiry`: those tokens have no `exp` claim
and will start failing with `401 invalid_token` the moment the new build is
live, with no grace period. Default-minted tokens (30-day `exp`, no lifetime cap
configured) are unaffected. Audit for any `--no-expiry` tokens in active use and
reissue them with an expiry before or immediately after this deploy.

## Audit Log Tamper-Proofing

Every log entry includes:
- `event_signature`: HMAC of (previous_signature + event_content)
- `previous_signature`: Links to the prior record
- `sequence`: a monotonic per-process counter, itself inside the HMAC-signed
  fields, so it cannot be altered without breaking the signature

This creates a cryptographically verifiable chain. See `AuditLogger.log_decision()` for implementation. The chain is independently verifiable from the persisted log via `terminus.audit.verify.verify_audit_chain`, which reconstructs each signed payload from the stored fields and recomputes the HMAC without trusting the log's own assertions. Known limitation: the chain is process-scoped and resets to genesis on restart; durable cross-restart chaining is a planned enhancement.

**Audit events are versioned.** Each event carries a signed `schema_version` (currently `3`). v2 added two signed fields for the MCP enforcement point, `mcp_tool` and `mcp_approval_status` (`null` on the HTTP `/intercept` path), so the tool that ran and the outcome of any human approval are covered by the HMAC, not just recorded as metadata key names. v3 adds three signed graduated-autonomy evidence fields: `enforcement_mode` (default `"enforce"`), `would_deny` (default `false`), and `would_deny_reason_code` (default `null`), so a softened decision and what enforcement would have done are tamper-evident. `verify_audit_chain` selects the signed field set per line by its `schema_version`: lines with none are the original v1 set and lines with `2` use a frozen v2 set, so history captured before each change keeps verifying; any other version fails closed with `unknown_schema_version` rather than being guessed at or skipped. See [docs/capabilities/audit.md](docs/capabilities/audit.md) for the full field list.

**Tail truncation is now detectable, with a trust-boundary caveat.** Chaining
alone cannot prove an attacker who can write the log store did not delete the
most recent events; a shorter, truncated chain still verifies clean on its own.
Two additions close that gap: the signed `sequence` field lets
`verify_audit_chain` detect a broken continuity (`sequence_gap`, which also
catches a middle deletion or reorder), and Terminus can emit a distinct,
itself-HMAC-signed `terminus_audit_checkpoint` line carrying the current chain
head (`boot_id`, `sequence`, `head_signature`, `checkpoint_time`) every
`TERMINUS_AUDIT_CHECKPOINT_INTERVAL` decision events and once on graceful
shutdown. Passing a captured checkpoint's head into `verify_audit_chain` as
`expected_head_sequence` / `expected_head_signature` fails a short chain with
`tail_truncation`. This detection is only as strong as the out-of-band
capture: a hash chain cannot prove its own missing suffix, so it holds only to
the extent the checkpoint is captured somewhere the log-store attacker does
not control (an external SIEM, not the same mutable log store or volume). The
residual exposure window is whatever was written since the last *captured*
checkpoint, bounded by `TERMINUS_AUDIT_CHECKPOINT_INTERVAL`; a whole segment
deleted before any checkpoint is captured is not caught by this mechanism and
is mitigated operationally by liveness monitoring instead.

## Signature privacy guarantee

Terminus extracts a structural signature from denied and suspicious queries.
A signature is designed so that even if the signature stream is read by a wider
audience than the source database itself, no schema identifiers and no row data
are exposed. A signature carries only: operation kinds, structural
booleans/counts, role classes from a fixed vocabulary (`restricted`,
`allowlisted`, `unrestricted`, `aggregate`, `unattributed`, `unlisted`), operator
classes from a fixed vocabulary, our own smuggling-pattern names, and a
deterministic hash over those abstract facts. Table names, column names, and
literal values are never included.

Enforcement is structural and fail closed:
- A single chokepoint (`to_signature_facts`) is the only code permitted to see
  real identifiers; it converts them to role classes and drops the names.
- All downstream types are name-free by construction.
- A privacy guard validates every token against its vocabulary immediately
  before emission; an unexpected token drops the signature and logs only the
  offending field name.
- Signature work is wrapped so it can never alter an allow/deny decision.

## Configuration

All security settings are controlled via environment variables prefixed with `TERMINUS_`:

- `TERMINUS_AUDIT_HMAC_KEY` – Secret for signing logs (must be >=32 bytes in production)
- `TERMINUS_RATE_LIMIT_PER_MINUTE`
- `TERMINUS_POLICY_PATH`
- `TERMINUS_SCHEMA_WHITELIST_PATH`
- `TERMINUS_REDIS_URL`

**Never commit real secrets.** Use `.env` files or Kubernetes Secrets in production.

**Production secret guard.** When `TERMINUS_ENVIRONMENT` is anything other than
`development`, Terminus refuses to start (raises at startup, aborting the boot)
if `TERMINUS_JWT_SECRET` or `TERMINUS_AUDIT_HMAC_KEY` is left at its shipped
default value. The length check alone cannot tell a real secret from the public
default, so the default keys would otherwise run silently with a forgeable audit
chain and spoofable agent identity. Set real secrets, or set
`TERMINUS_ENVIRONMENT=development` for local/demo use (the bundled Docker stack
does the latter).

**Multi-worker boot guard.** The audit HMAC chain, velocity trackers, and
signature store are per-process globals: running more than one worker would
silently split the audit chain into interleaved, independently-rooted
segments and multiply the effective velocity thresholds, without any error.
This is now fail-fast at boot: in `staging` and `production`, Terminus refuses
to start when more than one worker is detected (via `TERMINUS_WORKER_COUNT`,
`WEB_CONCURRENCY`, or the parent process command line), the same fail-closed
pattern as the secret guard above. `development` only warns and boots.
`TERMINUS_ALLOW_UNSAFE_MULTI_WORKER=true` is a named escape hatch that boots
anywhere with a loud warning; using it voids the audit and velocity
guarantees for as long as more than one worker is running. Scale
horizontally, one worker per container/pod, instead.

**API surface in hardened environments.** In `staging` and `production`,
Terminus disables the interactive API documentation surfaces by default:
`/docs` (Swagger UI), `/redoc` (ReDoc), and `/openapi.json` (the OpenAPI
schema itself) return 404 instead. These endpoints leak the full service schema,
version, and endpoint inventory to any network-adjacent observer and are
recon surfaces for attackers. The root `/` endpoint omits the `docs` link when
disabled, preventing dangling links and confirming the docs exist. The default
can be overridden per-deployment via `TERMINUS_DISABLE_DOCS=false` if your
network layer already controls access (e.g. firewall, ingress policy). In
`development`, all documentation surfaces are served by default for operational
ease. The `/metrics` Prometheus endpoint is a separate control: it is served on
all environments but should be restricted at the network layer (see
`docs/operations.md`), never on the default public path.

## Signature matching and bundle distribution

The signature intelligence subsystem matches queries against known-bad fingerprints
and updates that set from signed bundles. Two properties protect it:

- **Privacy:** matching and storage use only the abstracted `query_fingerprint` and
  name-free metadata, the same ceiling as the Phase 1 extractor. No table names,
  column names, or literals are stored, matched, or shipped.
- **Supply chain:** bundles are Ed25519-signed. The Hub holds the private key; each
  sidecar pins only the public key and can verify but never forge a bundle. A
  verification failure is loud (ERROR log) but safe: the last-known-good set is kept
  and no unverified data is ever applied. The primary new threat is malicious bundle
  injection, and asymmetric signing is what neutralizes it. The Hub private key must
  be protected with HSM-grade controls.

Matching is opt-in and observe-first: enable matching, watch the "would have blocked"
telemetry with enforce disabled, then enable enforcement. Local overrides (disable, mode
override, local-authored signatures) always win over bundle defaults.

### Velocity / sequence detection (F9)

Terminus tracks per-agent query velocity to flag a blind-extraction oracle
(many individually-allowed queries that together reconstruct restricted
data). It is a behavioral guardrail in the same fail-open tier as rate
limiting, not part of the fail-closed core: it observes by default (raising
`velocity_anomaly` in the audit chain and a metric) and can be armed to deny
(`TERMINUS_VELOCITY_ENFORCE_ENABLED`), where it only ever escalates an allow
to a deny and never overrides an existing deny. Retained state is name-free
(agent id, fingerprint hash, window, count) and memory-bounded. Enforce
requires an authenticated (JWT-verified) agent identity; unauthenticated or
self-asserted traffic is observe-only (flagged, never denied), since a
self-asserted agent id is spoofable and would otherwise let an attacker drive
a cross-agent deny. Authenticated and unauthenticated traffic are tracked in
separate, independently bounded tracker pools, not just a separate key
namespace within one shared pool, so an unauthenticated agent can neither
poison nor, by flooding the shared LRU with unique self-asserted ids, evict
or reset an authenticated agent's enforcement counter. Known limitations:
in-process state is per-replica in v1, and velocity does not catch a
low-and-slow attacker.

## Outbound telemetry (Phase 2B)

Outbound telemetry is the only part of Terminus that sends data out of your environment,
and it is opt-in and default-off. Two properties bound it:

- **Privacy:** the outbound payload is a strict, name-free projection of a signature that
  has already passed the privacy guard, and the outbound path re-runs that guard fail-closed
  before queuing. It carries only an abstracted fingerprint, structural role classes, the
  technique label, the sidecar's own decision and risk score, and a coarse hourly timestamp.
  Table names, column names, literals, agent ids, request ids, hosts, and audit data are never
  sent.
- **Containment:** delivery is best-effort and entirely off the request path. A bounded buffer
  drops oldest on overflow; a background shipper batches, retries, then drops on failure. A Hub
  outage, a slow Hub, or a bug in the outbound path can never change a decision or 500 a request.

Authentication to the Hub uses an optional bearer token in v1; mutual TLS or signed requests can
replace it later without changing the shipper. With outbound disabled (the default), no buffer or
background task exists and there is zero egress.

## MCP enforcement point

The HTTP sidecar (`/intercept`) is advisory: the agent still holds the database
credentials and has to choose to obey the decision. `python -m terminus.mcp` is a
reference implementation that removes that choice: the agent talks only to an MCP
server exposing `query` (read-only) and `execute` (writes) tools, never receives a
database connection string, and has no path to the database except through those
two tools. The same parser and policy engine decide every call, in-process, before
anything runs (a Policy Decision Point, per NIST SP 800-207); the MCP server is the
Policy Enforcement Point, structurally unable to run SQL without a decision, since
its executor accepts only a grant minted by an allow (`ExecutionGrant`, never a raw
statement), and nothing else in the package constructs one. High-risk writes (a
policy allow at or above `TERMINUS_MCP_APPROVAL_RISK_THRESHOLD`) are held for human
approval rather than executed immediately, fail-closed on timeout, deny, or a
crashed broker. There is no degraded or fail-open mode anywhere in this path;
availability comes from redundant replicas, never from bypassing a decision. As
of audit schema v2, the tool identity and the approval outcome for every MCP
call are signed, first-class fields in the audit chain above, not just
metadata key names. Full
detail, including the credential-isolation topology, the break-glass approval
flow, the audit binding, and honestly-scoped MVP limitations, is in
[docs/capabilities/mcp-enforcement-point.md](docs/capabilities/mcp-enforcement-point.md).

## Graduated autonomy (per-agent observe-to-enforce)

Graduated autonomy lets an operator run a specific, registered agent in
observe mode, softening certain policy denies to an allow-with-evidence so
the operator can review what enforce would have blocked before promoting the
agent, rather than blocking it outright from day one. It is a security-posture
feature, not a convenience one: it decides who gets a softer decision and
never touches how the decision itself is computed. `policy_engine.evaluate()`
is unmodified and stays trust-unaware; the transform runs strictly after it,
on both the HTTP and MCP enforcement surfaces
(`src/terminus/policy/graduated.py`). Full model, including the exact
allowlist and every fail-safe default, is in
[docs/capabilities/graduated-autonomy.md](docs/capabilities/graduated-autonomy.md).

**The floor is an allowlist, not a denylist.** Only five deny `reason_code`s
are ever softenable: `schema_whitelist`, `column_whitelist`, `policy_rule`,
`risk_threshold`, `default`. Every engine-level deny code outside that list,
`invalid_sql`, `oversize_sql`, `multi_statement`, `injection_function`,
`nested_write`, and MCP's `wrong_tool`, is floor: denied even for an
observe-mode agent, with no setting that changes that. The two post-decision
guardrail deny codes, `signature_match` and `velocity_anomaly`, sit outside
the allowlist too, by a different mechanism: their escalation-to-deny is
itself gated on the agent being in enforce mode, so an observe agent can
never receive them at all. Because the list is an allowlist, any new deny
`reason_code` added to the engine in the future is floor by default until
someone deliberately adds it to the allowlist; graduated autonomy cannot
silently start softening a control nobody reviewed for it.

**The spoofing rule (F9 lesson, inverted).** Observe-mode softening is
honored only for an unspoofable identity: a JWT-verified `sub` on HTTP
(`agent_authenticated=True`), or the operator-set, boot-validated
`TERMINUS_MCP_AGENT_ID` on MCP. A self-asserted `agent_id` on the legacy
unauthenticated HTTP path always resolves to enforce, even when that same id
is registered `trust_level: observe`, because `resolve_enforcement_mode`
checks `agent_authenticated` before it ever consults the registry
(`src/terminus/policy/graduated.py`). This mirrors the F9 velocity
guardrail's identity rule, inverted: F9 keeps a spoofed identity from driving
someone else's traffic into a deny; graduated autonomy keeps a spoofed
identity from claiming someone else's softer posture. Deployments using
graduated autonomy should run with `TERMINUS_REQUIRE_AUTH=true` so every
agent that is meant to benefit from observe mode actually can.

**Promotion is a signed, chained audit event.** A trust-level change is never
a silent config edit. Every applied governance reload diffs old vs. new
registry `trust_level` per agent and, for each agent whose effective trust
changed, emits a signed `terminus_trust_level_change` event into the SAME
HMAC chain as decision events (shared lock, shared running signature, its own
frozen signed-field set), so a promotion or demotion is exactly as
tamper-evident as a policy decision and cannot be deleted or reordered
without breaking the chain. See
[docs/capabilities/audit.md](docs/capabilities/audit.md) for the event's
fields and how the verifier dispatches across both event kinds.

**Switch-off equivalence is a tested regression guarantee, not a claim.**
`TERMINUS_GRADUATED_AUTONOMY_ENABLED` defaults to `false`. Off,
`resolve_enforcement_mode` returns `"enforce"` before it ever reads the
registry, so every `trust_level` entry in `agents.yaml` is inert and behavior,
including the audit v3 defaults (`enforcement_mode="enforce"`,
`would_deny=false`, `would_deny_reason_code=null`), is byte-for-byte
identical to a deployment that never enabled the feature at all.

**Break-glass composition (MCP): softening a policy deny never softens a
human-approval requirement.** A softened decision still flows through the
same high-risk-write check as any other allow: if the operation is a write
and its risk score is at or above `TERMINUS_MCP_APPROVAL_RISK_THRESHOLD`, it
returns `NeedsApproval` and waits for a human exactly as an
ordinarily-allowed high-risk write would. Observe relaxes a policy deny; it
never relaxes the break-glass valve, and floor denies never reach the point
where a grant could be minted, observe or not.

---

## Container posture

The shipped `Dockerfile` is multi-stage: a `builder` stage installs the app
(including its compiler toolchain, `build-essential`) into a self-contained
venv, and the runtime stage copies only that venv across. The runtime image
carries no compiler toolchain and no dev tooling (pytest, mypy, ruff, black,
isort are never installed there; the app is installed without its `[dev]`
extra). The runtime stage runs as a dedicated non-root `terminus` user;
application code and configuration under `/app` are owned by root and are
readable and executable, but not writable, by the process user, so a
compromised process cannot modify its own code or config on disk. `make
docker-smoke` is the local, pre-deploy check for this posture (build, then
assert non-root and a healthy `/health`); see the "Hardening for production"
checklist in [docs/operations.md](docs/operations.md#hardening-for-production)
for the full pre-production checklist this container posture is one part of.

---

*Last updated: 2026-07-08*