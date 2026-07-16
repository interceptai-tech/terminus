# Terminus Configuration Reference

Every Terminus setting is an environment variable. This is the authoritative
reference: each variable lists its default, type, what it actually does
(including the observable symptom when it is wrong), when you would change it,
and which other variables it interacts with. The README carries a quick-glance
grid; this document is the depth behind it.

## How configuration is loaded

- **Prefix.** Every variable is prefixed `TERMINUS_` and matched
  **case-insensitively** (`TERMINUS_REDIS_URL` sets `redis_url`). Conventional
  UPPERCASE works.
- **No `.env` file.** `.env` loading is deliberately disabled so that container
  and orchestrator environment variables always take precedence. Do not rely on
  a `.env` file in a deployed container; it will be ignored.
- **Precedence and loading order.** The value comes from the process environment
  if set, otherwise the built-in default. There is no file fallback in between.
  Settings are read once and cached at first use, so a change requires a process
  restart to take effect.
- **Defaults are dev-grade, not prod-grade.** Several defaults (the JWT secret,
  the audit HMAC key, the example policy/whitelist/registry paths) are
  intentionally insecure or illustrative so local development works with zero
  setup. Every production deployment must override the sensitive ones. The
  "must override in production" set is listed at the end.

---

## 1. Runtime and service

Most of these are process-level knobs; entries below note when a setting
changes security posture.

**`TERMINUS_ENVIRONMENT`**
- **Default:** `production`. **Type:** `development` | `staging` | `production`.
- **Impact:** a label used by `/health` and the `terminus_build_info` metric,
  and the switch for the production secret guard. When it is anything other than
  `development`, startup fails if `TERMINUS_JWT_SECRET` or
  `TERMINUS_AUDIT_HMAC_KEY` is still the shipped default (see those entries).
  Environment now also keys hardened defaults: in `staging` and `production`,
  `TERMINUS_JWT_REQUIRE_EXP` defaults to `true`, `TERMINUS_DISABLE_DOCS` defaults
  to `true`, `TERMINUS_AUDIT_CHECKPOINT_INTERVAL` defaults to `1000`, and the
  multi-worker boot guard refuses to start instead of warning. An explicit env
  var always overrides the auto default.
- **When to change:** set it to match the real environment so your dashboards
  and alerts attribute data correctly, and so the secret guard is active. Use
  `development` only for local/demo work with the example secrets.
- **Interacts with:** `TERMINUS_JWT_SECRET`, `TERMINUS_AUDIT_HMAC_KEY` (the guard),
  `TERMINUS_JWT_REQUIRE_EXP`, `TERMINUS_DISABLE_DOCS`, `TERMINUS_AUDIT_CHECKPOINT_INTERVAL`,
  `TERMINUS_ALLOW_UNSAFE_MULTI_WORKER`.

**`TERMINUS_LOG_LEVEL`**
- **Default:** `INFO`. **Type:** `DEBUG` | `INFO` | `WARNING` | `ERROR`.
- **Impact:** structlog verbosity. Most operationally useful signals (rate-limit
  skips, auth fallbacks, signature guard trips, bundle update failures) are
  emitted at WARNING. Symptom of setting it to `ERROR`: those events go silent
  and you lose the breadcrumbs that explain odd behavior at 2am.
- **When to change:** `DEBUG` while diagnosing; `INFO` normally.
- **Interacts with:** nothing functional.

**`TERMINUS_HOST`**
- **Default:** `0.0.0.0`. **Type:** string (bind address).
- **Impact:** the interface the server binds. `0.0.0.0` listens on all
  interfaces (normal for a container).
- **When to change:** `127.0.0.1` to restrict to loopback; otherwise leave it.
- **Interacts with:** your network/deployment.

**`TERMINUS_PORT`**
- **Default:** `8000`. **Type:** int.
- **Impact:** the port the server binds.
- **When to change:** to fit your network or to avoid a conflict.
- **Interacts with:** your network/deployment.

**`TERMINUS_RELOAD`**
- **Default:** `false`. **Type:** bool.
- **Impact:** uvicorn auto-reload on code change. Development only. Symptom of
  leaving it on in production: worse performance and surprise worker restarts.
- **When to change:** `true` for local development only.
- **Interacts with:** nothing functional.

**`TERMINUS_CONFIG_RELOAD_INTERVAL`**
- **Default:** `0` (off). **Type:** int seconds.
- **Impact:** when > 0, the sidecar re-reads policy.yaml, schema_whitelist.yaml,
  and agents.yaml every N seconds and atomically hot-swaps on change, keeping
  last-known-good on a bad config (no restart needed, including live agent
  revocation). 0 loads once at startup.
- **When to change:** set to e.g. 30-300 in a GitOps deployment where a sidecar
  (git-sync, ConfigMap, Argo, Flux) keeps the files current.
- **Interacts with:** `TERMINUS_POLICY_PATH`, `TERMINUS_SCHEMA_WHITELIST_PATH`,
  `TERMINUS_AGENT_REGISTRY_PATH`.

**`TERMINUS_DISABLE_DOCS`**
- **Default:** auto: `false` in development, `true` in staging/production. **Type:** bool.
- **Impact:** when `true`, the FastAPI documentation endpoints (`/docs`, `/redoc`,
  `/openapi.json`) are removed from the app. Production deployments should hide
  these endpoints from the internet to reduce reconnaissance surface; in development,
  they are useful for manual testing and debugging.
- **When to change:** override to `false` in staging/production only as an unsafe
  compatibility escape if you rely on the auto-generated docs behind network
  controls. The hardened default assumes docs are internet-facing without additional
  protections.
- **Interacts with:** `TERMINUS_ENVIRONMENT`.

**`TERMINUS_WORKER_COUNT`**
- **Default:** unset (auto-detect). **Type:** int (>= 1).
- **Impact:** operator attestation of the deployment's worker count, used by the
  multi-worker boot guard. When set, the value is authoritative: no other
  detection signal is consulted. If it is greater than 1, the guard fails
  closed (refuses to boot) in staging/production, warns and boots in
  development, or boots with a warning anywhere `TERMINUS_ALLOW_UNSAFE_MULTI_WORKER`
  is set. When unset, the guard falls back to the `WEB_CONCURRENCY` convention
  and then to parsing the parent process command line, before assuming a
  single worker. This field prevents accidental silent fragmentation of the
  audit chain, velocity trackers, and signature store in a multi-worker
  deployment.
- **When to change:** always in production. Set it to the number of workers
  configured for this Terminus instance (e.g. `4` for a 4-worker uvicorn pool).
  Leave it unset for single-worker deployments.
- **Interacts with:** `TERMINUS_ALLOW_UNSAFE_MULTI_WORKER`.

**`TERMINUS_ALLOW_UNSAFE_MULTI_WORKER`**
- **Default:** `false`. **Type:** bool.
- **Impact:** when set to `true`, the multi-worker boot guard emits a loud warning
  instead of failing. This is a compatibility escape only for deployments that
  know they are multi-worker and accept the risk of audit chain, velocity, and
  signature store fragmentation across workers. The name intentionally carries
  the risk. Symptom of setting this to `true`: you lose the isolation guarantees
  of single-process caches, and the audit trail becomes incomplete if any
  truncation event occurs.
- **When to change:** never, in production. Only for local testing or migrations
  where you understand the risk. Set `TERMINUS_WORKER_COUNT` instead.
- **Interacts with:** `TERMINUS_WORKER_COUNT`.

---

## 2. Policy and schema

The default-deny core. Both files are evaluated on every query; the schema
whitelist is checked before the policy rules.

**`TERMINUS_POLICY_PATH`**
- **Default:** `examples/policy.yaml`. **Type:** path.
- **Impact:** the policy rules file (priority-ordered match/action; default
  action is deny). The shipped example is a demo. Symptom of leaving it at the
  example in production: your real tables, agents, and operations are not
  governed the way you think, queries are allowed or denied per the demo rules.
- **When to change:** always in production. Point it at your own policy file.
- **Note:** Honored once a governance load occurs (the hot-reload manager reads
  this path). Defaults to the bundled example.
- **Interacts with:** `TERMINUS_SCHEMA_WHITELIST_PATH` (the whitelist is
  evaluated first; a query denied there never reaches policy rules).

**`TERMINUS_SCHEMA_WHITELIST_PATH`**
- **Default:** `examples/schema_whitelist.yaml`. **Type:** path.
- **Impact:** the default-deny allow-list of referenceable tables, with optional
  per-table column allow-lists. Checked before policy rules. Symptom: a query
  touching a non-whitelisted table is denied with `reason_code=schema_whitelist`
  even if a policy rule would have allowed it, and a query selecting a
  non-allowed column on a column-restricted table is denied with
  `reason_code=column_whitelist`.
- **When to change:** always in production. Point it at your own whitelist.
- **Note:** Honored once a governance load occurs (the hot-reload manager reads
  this path). Defaults to the bundled example.
- **Interacts with:** `TERMINUS_POLICY_PATH`.

**`TERMINUS_SQL_DIALECT`**
- **Default:** empty (generic/Postgres lowercase). **Type:** string (a sqlglot
  dialect name, e.g. `postgres`, `snowflake`, `bigquery`, `mysql`, `duckdb`).
- **Impact:** the deployment database's SQL dialect. It drives identifier
  normalization for both incoming queries and the schema whitelist / policy
  table and column patterns, so case-folding of unquoted identifiers follows
  that database's rules (for example Snowflake folds unquoted identifiers to
  UPPERCASE, not lowercase). An unknown value refuses to boot, rather than
  silently falling back to lowercase folding.
- **When to change:** set it to the dialect of the database your agents
  actually query, if that database is not PostgreSQL or another
  lowercase-folding database. Leave it empty for PostgreSQL.
- **Validated dialects:** PostgreSQL (default/empty) is validated end-to-end,
  including the MCP enforcement executor (`python -m terminus.mcp`).
  `snowflake` is corpus-validated and shadow-ready: the PoV harness
  (`TERMINUS_SQL_DIALECT=snowflake PYTHONPATH=src uv run python -m pov.harness
  --corpus pov/corpus_snowflake.yaml`) passes a dedicated Snowflake corpus at
  the Postgres-equivalent accuracy gate, but no Snowflake executor exists yet,
  so this dialect covers the `/intercept` decision API only; the caller
  executes the SQL and holds the credentials itself. Other listed dialects
  are parsed by sqlglot but not corpus-validated.
- **Known limitation:** whitelist/policy identifiers are folded as unquoted
  per this dialect's case rules, so a genuinely quoted mixed-case object
  (for example Snowflake's `"Orders"`) can never match the folded whitelist
  entry and is denied: a fail-closed over-deny, not a bypass (see
  `docs/capabilities/policy-and-whitelists.md`). Workaround: name objects
  unquoted so they fold naturally, or write the whitelist entry in the
  dialect's folded case.
- **Interacts with:** `TERMINUS_POLICY_PATH`, `TERMINUS_SCHEMA_WHITELIST_PATH`
  (both are normalized against this dialect on load).

**`TERMINUS_ENFORCE_INJECTION_BLOCK`**
- **Default:** `true`. **Type:** bool.
- **Impact:** when `true`, a query that calls an injection or time-based SQL
  function (`pg_sleep`, `sleep`, `benchmark`, `waitfor`, `xp_cmdshell`,
  `pg_read_file`, ...) is denied on the core path with
  `reason_code=injection_function`, even if a policy rule would otherwise allow
  it. Detection is AST-based (function-node name), so type names like
  `varchar(255)` are never affected. When `false`, the signal is observe-only:
  it still appears in `risk_reasons` and the smuggling metric, but the decision
  is unchanged. Symptom of `false` in production: an injection or time-based
  function on an approved table is allowed.
- **When to change:** set `false` for a one-deploy migration if you want to
  watch the `injection_function` "would-block" signal before enforcing; leave
  it `true` otherwise.
- **Interacts with:** the schema whitelist and policy rules. The gate runs
  after the whitelist and column checks and before the rule loop, so it only
  ever escalates an otherwise-allow to a deny.

**Nested-write gate (no environment variable).** Independent of the flag above,
Terminus also denies a data-modifying operation (INSERT, UPDATE, DELETE, MERGE)
hidden inside a CTE, for example `WITH d AS (DELETE FROM t RETURNING id) SELECT
1`, which is otherwise classified as SELECT and would never reach the
destructive-operation policy rules that govern DELETE. This gate runs after the
schema whitelist, column whitelist, and injection-function gate, and before the
policy rule loop, denying with `reason_code=nested_write`. Unlike
`TERMINUS_ENFORCE_INJECTION_BLOCK`, there is no toggle for this: under a
default-deny posture, a write smuggled inside a CTE has no benign reading.

**`TERMINUS_MAX_SQL_LENGTH`**
- **Default:** `16384` (16 KiB, characters). **Type:** int (> 0).
- **Impact:** the maximum SQL length the parser accepts. A query longer than
  this is denied with `reason_code=oversize_sql` before it is parsed, so a
  single large or pathological statement cannot block the async event loop
  (parse cost scales with length). Symptom of setting it too low: legitimate
  large queries (big `IN (...)` batches, wide generated SQL) start returning
  403 `oversize_sql`.
- **When to change:** raise it only after load-testing parser p99 for your
  workload. The default is roughly 100x the largest realistic agent query.
- **Interacts with:** two coarser caps sit above it. The `sql` field is capped at
  128 KiB characters (a schema `422`), and the whole request body is capped by
  `TERMINUS_MAX_REQUEST_BODY_BYTES` (a `413` rejected before parsing).
  `TERMINUS_MAX_SQL_LENGTH` must stay below both so an over-cap query is an
  audited `deny`, not a bare validation error.

**`TERMINUS_MAX_REQUEST_BODY_BYTES`**
- **Default:** `262144` (256 KiB, bytes). **Type:** int (> 0).
- **Impact:** the maximum size of any request body. A larger body is rejected
  with `413` before it is read into memory or JSON-parsed, so an oversized payload
  (a huge `sql`, or huge `metadata`, which is otherwise unbounded) cannot burn
  memory in the request path. Keep it above the 128 KiB `sql` field cap to leave
  room for the JSON envelope and metadata.
- **When to change:** rarely; raise it only if a legitimate client sends larger
  bodies. A hard network-layer body limit still belongs at your reverse proxy or
  service mesh; this is the app-layer backstop.
- **Interacts with:** `TERMINUS_MAX_SQL_LENGTH` (keep this above it).

---

## 3. Rate limiting and Redis

Per-agent throttling on `/intercept`. Rate limiting is a guardrail and **fails
open**: a Redis outage disables the limit but never blocks SQL validation.

**`TERMINUS_REDIS_URL`**
- **Default:** `redis://redis:6379`. **Type:** string (connection URL; may embed
  `user:password`, which is stripped from logs).
- **Impact:** the Redis instance backing the rate limiter. If Redis is
  unreachable, the limiter fails open: the limit is skipped and core protection
  keeps running. Symptom: at startup you see `rate_limiter_unavailable`, and
  per request `rate_limit_skipped`; no client ever receives a 429.
- **When to change:** point it at your Redis. Leave the default in the bundled
  Docker stack.
- **Interacts with:** `TERMINUS_RATE_LIMIT_PER_MINUTE` (meaningless if Redis is
  down, since nothing is enforced).

**`TERMINUS_RATE_LIMIT_PER_MINUTE`**
- **Default:** `10`. **Type:** int.
- **Impact:** the per-agent request budget on `/intercept`, keyed by the trusted
  (or self-asserted) agent id, falling back to client IP. Symptom of setting it
  too low: legitimate agents start getting `429 Too Many Requests` with no other
  obvious cause.
- **When to change:** size it to your busiest legitimate agent's request rate.
- **Interacts with:** `TERMINUS_REDIS_URL`. It is the only active rate limit:
  the per-policy `max_queries_per_minute` field in `policy.yaml` is parsed but
  not enforced in v0, and the governance loader logs
  `policy_limit_not_enforced` for any rule that sets it.

---

## 4. Audit

The tamper-evident audit log signs each event with HMAC-SHA256 and chains it to
the previous one.

**`TERMINUS_AUDIT_HMAC_KEY`**
- **Default:** an insecure placeholder. **Type:** string (>= 32 bytes).
- **Impact:** the key that signs and chains the audit log. The default is
  published in this repo: with it, the audit chain is forgeable and provides no
  integrity guarantee. Guard: when `TERMINUS_ENVIRONMENT` is not `development`,
  Terminus **refuses to start** if this is left at the default (fail fast).
  Symptom in `development`: no error, the chain is simply worthless until you set
  a real key.
- **When to change:** always in production. Set a random >= 32-byte key and keep
  it stable; rotating it breaks chain continuity across the rotation point.
- **Interacts with:** nothing functional (read case-insensitively like all
  vars).

**`TERMINUS_AUDIT_CHECKPOINT_INTERVAL`**
- **Default:** auto: `0` in development, `1000` in staging/production. **Type:** int (count of decision events).
- **Impact:** when `> 0`, Terminus emits a distinct, itself-HMAC-signed
  `terminus_audit_checkpoint` log line carrying the current chain head
  (`boot_id`, `sequence`, `head_signature`, `checkpoint_time`) every N decision
  events, plus one more on graceful shutdown. `0` means no checkpoint is ever
  emitted. The interval is amortized by design, not a per-event fsync, so it
  never touches the < 2 ms p99 parser latency budget. Symptom: the setting is
  inert by itself; it only becomes load-bearing once the checkpoint line is
  shipped to and captured by something outside the mutable audit store, an
  external SIEM, not the same log volume an attacker could also write to (see
  audit-to-siem.md). Note: an explicit `0` in any environment disables periodic
  and shutdown checkpoints, reopening the GAPS M2 restart/truncation exposure.
- **When to change:** set it once a SIEM/aggregator is actually capturing the
  checkpoint line, to bound the tail-truncation exposure window. A smaller
  value shrinks that window at the cost of more checkpoint lines.
- **Interacts with:** `TERMINUS_AUDIT_HMAC_KEY` (the checkpoint is signed with
  the same key); the verifier's `expected_head_sequence` /
  `expected_head_signature` parameters (see docs/capabilities/audit.md).

---

## 5. Agent identity (JWT)

Verifiable per-agent identity. The full trust model is in SECURITY.md.

**`TERMINUS_JWT_SECRET`**
- **Default:** an insecure dev placeholder. **Type:** string (>= 32 bytes).
- **Impact:** the HS256 secret used to verify agent Bearer JWTs. The default is
  publicly known: anyone can mint a token for any agent id and impersonate it,
  and every per-agent control becomes spoofable. Guard: when
  `TERMINUS_ENVIRONMENT` is not `development`, Terminus **refuses to start** if
  this is left at the default (fail fast).
- **When to change:** always, in any non-local deployment. Generate a random
  >= 32-byte secret and inject it via your secret manager.
- **Interacts with:** `TERMINUS_REQUIRE_AUTH`, `TERMINUS_AGENT_REGISTRY_PATH`.

**`TERMINUS_REQUIRE_AUTH`**
- **Default:** `false`. **Type:** bool.
- **Impact:** when `true`, a request with no Bearer JWT is rejected with 401 and
  the legacy self-asserted-id path is disabled. When `false`, an absent token
  falls back to the self-asserted `agent_id` (a migration aid). An *invalid*
  token is always 401 regardless of this flag. Symptom of `false` in production:
  callers can still self-assert any `agent_id` by simply not sending a token.
- **When to change:** set `true` once all your agents present JWTs.
- **Interacts with:** `TERMINUS_JWT_SECRET`, `TERMINUS_AGENT_REGISTRY_PATH`.

**`TERMINUS_AGENT_REGISTRY_PATH`**
- **Default:** `examples/agents.yaml`. **Type:** path.
- **Impact:** the allow-list of agent `sub` values accepted for authentication.
  An unknown or disabled `sub` is rejected even with a valid signature, this is
  how you revoke an agent without rotating the shared secret. Symptom: a
  previously working agent gets 401 after you remove or disable its entry (the
  intended revocation behavior).
- **When to change:** point it at your real registry; edit it to add or disable
  agents.
- **Interacts with:** `TERMINUS_REQUIRE_AUTH`, `TERMINUS_JWT_SECRET`.

**`TERMINUS_JWT_REQUIRE_EXP`**
- **Default:** auto: `false` in development, `true` in staging/production. **Type:** bool.
- **Impact:** when `true`, a JWT without an `exp` claim is rejected with 401. The
  `exp` claim (expiration time) is how you encode token lifetime; a missing claim
  means the token never expires, which violates standard JWT practice and makes
  token rotation harder to enforce. In production, requiring `exp` is a hardened
  default for credential hygiene.
- **When to change:** override to `false` in production only as an unsafe
  compatibility escape if legacy agents mint tokens without `exp`. This is a
  one-way compatibility override, not a permanent setting (audit and plan agent
  updates).
- **Interacts with:** `TERMINUS_JWT_MAX_LIFETIME_SECONDS` (when that is `> 0`, both
  `exp` and `iat` become required). `TERMINUS_ENVIRONMENT`.

**`TERMINUS_JWT_MAX_LIFETIME_SECONDS`**
- **Default:** `0` (no cap). **Type:** int seconds (>= 0).
- **Impact:** when `> 0`, the JWT's *minted* lifetime (`exp` - `iat`, in seconds)
  must not exceed this value, or the token is rejected with 401 (fail-closed). A
  `max_lifetime` of 3600 means "no token older than one hour at issuance"; it
  complements `exp` for tokens that were minted far in the future (e.g. a developer
  accidentally grants a one-year token). When `> 0`, both `exp` and `iat` become
  required claims; a missing claim triggers a 401. `0` disables the check entirely.
- **When to change:** set it once you have a target token lifetime policy (e.g.
  "no agent token minted for more than 1 hour"). Start with `3600` and lower if
  your agents rotate more frequently.
- **Interacts with:** `TERMINUS_JWT_REQUIRE_EXP` (when this is `> 0`, `exp` and
  `iat` are required).

---

## 6. Signature extractor

The privacy-preserving extractor that turns denied and suspicious queries into
name-free structural signatures on the dedicated `terminus.signature` log
stream. This is the data source that the matching (section 7) and outbound
(section 8) features build on.

**`TERMINUS_SIGNATURES_ENABLED`**
- **Default:** `true`. **Type:** bool.
- **Impact:** master switch for signature extraction and emission. When `false`,
  no signature work runs (the parser also skips its extra fact collection).
  Symptom: with it off you get no `terminus_signature` log lines, and the
  outbound shipper has nothing to send (matching can still run on its own flag,
  but emission and outbound have no source).
- **When to change:** leave it on; it is privacy-safe (names and literals never
  appear in a signature) and it is the data the moat is built from. Turn it off
  only if you want pure enforcement with zero signature telemetry.
- **Interacts with:** `TERMINUS_SIGNATURE_RISK_THRESHOLD`,
  `TERMINUS_SIGNATURE_OUTBOUND_ENABLED` (outbound has no source without this on).

**`TERMINUS_SIGNATURE_RISK_THRESHOLD`**
- **Default:** `0.5`. **Type:** float (0.0 to 1.0).
- **Impact:** an *allowed* query whose `risk_score` is >= this value is treated
  as suspicious and emitted. Denies and smuggling/hidden-subquery queries are
  always emitted regardless. Symptom of setting it very low: the signature
  stream (and outbound volume) balloons with benign allowed queries.
- **When to change:** lower it to capture more borderline allows, raise it to
  reduce noise.
- **Interacts with:** `TERMINUS_SIGNATURES_ENABLED`, outbound volume.

---

## 7. Signature matching and inbound updates

Local detection: match each query's fingerprint against a known-bad set kept
fresh from signed bundles. Opt-in; off by default. See the signature flywheel
docs and SECURITY.md for the model.

**`TERMINUS_SIGNATURE_MATCHING_ENABLED`**
- **Default:** `false`. **Type:** bool.
- **Impact:** master switch for the matcher. When `true`, every query's
  fingerprint is computed and checked against the in-memory known-bad store.
  When `false`, Phase 1 behavior is unchanged and there is no per-query
  fingerprint cost. Symptom of off: the store is never consulted, so distributed
  signatures do nothing.
- **When to change:** turn it on to act on known-bad signatures.
- **Interacts with:** `TERMINUS_SIGNATURE_ENFORCE_ENABLED`,
  `TERMINUS_SIGNATURE_BUNDLE_SOURCE` (which feeds the store).

**`TERMINUS_SIGNATURE_ENFORCE_ENABLED`**
- **Default:** `false`. **Type:** bool.
- **Impact:** global posture. When `false`, every match is observe-only:
  annotate (`risk_reasons += signature_match`) and log, decision unchanged. When
  `true`, an enforce-mode signature can escalate a local ALLOW to a DENY
  (`reason_code=signature_match`). A local deny is never downgraded. Symptom of
  `true` with a false-positive signature: a legitimate query starts getting
  denied for `signature_match`.
- **When to change:** enable it only after watching observe-mode "would have
  blocked" telemetry and trusting the corpus.
- **Interacts with:** `TERMINUS_SIGNATURE_MATCHING_ENABLED` (no effect without
  it), per-signature mode, and the local overrides file.

**`TERMINUS_SIGNATURE_BUNDLE_SOURCE`**
- **Default:** `""`. **Type:** string (an HTTPS URL, `http` for internal
  sources, or a local file path).
- **Impact:** where signed bundles are pulled from. Empty means no inbound
  updates (the store stays empty or local-only). A local file path is the
  air-gapped mode. Symptom: empty while matching is on means nothing ever
  matches.
- **When to change:** point it at your Hub or bundle source (or a local file for
  air-gapped operation).
- **Interacts with:** `TERMINUS_SIGNATURE_BUNDLE_PUBLIC_KEY` (required to
  verify), `TERMINUS_SIGNATURE_POLL_INTERVAL`,
  `TERMINUS_SIGNATURE_OVERRIDES_PATH`.

**`TERMINUS_SIGNATURE_BUNDLE_PUBLIC_KEY`**
- **Default:** `""`. **Type:** string (a filesystem path or an inline PEM/base64
  value).
- **Impact:** the Ed25519 public key used to verify bundle signatures. Bundles
  are never applied without a valid signature against this key (fail-closed on
  trust). Symptom of a rotated or mismatched key: bundle updates start failing
  (ERROR `signature_bundle_update_failed`), the store keeps last-known-good, and
  you quietly stop receiving updates without an outage, watch the
  `terminus_signature_version_skew_total` and the update error logs.
- **When to change:** set it to the Hub's public key; update it on key rotation.
- **Interacts with:** `TERMINUS_SIGNATURE_BUNDLE_SOURCE` (required when a source
  is set).

**`TERMINUS_SIGNATURE_POLL_INTERVAL`**
- **Default:** `0`. **Type:** int (seconds).
- **Impact:** how often to re-pull the bundle. `0` means load once at startup
  and never poll. Symptom of `0`: you never pick up new signatures until the
  next restart.
- **When to change:** set it to, for example, 300 to 3600 seconds to keep the
  corpus fresh.
- **Interacts with:** `TERMINUS_SIGNATURE_BUNDLE_SOURCE`.

**`TERMINUS_SIGNATURE_OVERRIDES_PATH`**
- **Default:** `""`. **Type:** path.
- **Impact:** the local overrides file. It can disable a `signature_id`, force a
  signature's mode (observe/enforce), or add local-authored signatures. Local
  always wins over bundle defaults. Symptom/use: suppress a false-positive
  signature that is denying legitimate traffic without waiting for a new bundle.
- **When to change:** when you need to pin, disable, or add a signature locally.
- **Interacts with:** `TERMINUS_SIGNATURE_BUNDLE_SOURCE` (overrides are applied
  on top of bundle records).

---

## 8. Signature outbound telemetry

The only feature that sends data out of your environment. Opt-in, default-off,
and fully inert until both the switch and a URL are set. The payload is a
name-free projection of a signature; see SECURITY.md for the privacy and
containment model.

**`TERMINUS_SIGNATURE_OUTBOUND_ENABLED`**
- **Default:** `false`. **Type:** bool.
- **Impact:** opt-in switch to ship privacy-scrubbed signatures to a Hub. Off
  means no buffer is constructed, no background task runs, and no egress occurs.
  Symptom: off is zero egress; on without a URL ships nothing.
- **When to change:** enable it to contribute to the shared corpus (also set the
  URL).
- **Interacts with:** `TERMINUS_SIGNATURE_HUB_INGEST_URL` (needed to ship
  anything), `TERMINUS_SIGNATURES_ENABLED` (the source of what gets shipped).

**`TERMINUS_SIGNATURE_HUB_INGEST_URL`**
- **Default:** `""`. **Type:** string (HTTPS endpoint).
- **Impact:** the Hub ingest endpoint that outbound batches are POSTed to.
  Required when outbound is enabled. Symptom: enabled with an empty URL means
  signatures accumulate in the buffer and are eventually dropped, nothing is
  sent.
- **When to change:** set it to your Hub's ingest endpoint.
- **Interacts with:** `TERMINUS_SIGNATURE_OUTBOUND_ENABLED`,
  `TERMINUS_SIGNATURE_HUB_TOKEN`.

**`TERMINUS_SIGNATURE_HUB_TOKEN`**
- **Default:** `""`. **Type:** string.
- **Impact:** an optional bearer token sent as `Authorization: Bearer <token>`
  on outbound POSTs. Empty means no auth header is sent.
- **When to change:** set it if the Hub requires authentication.
- **Interacts with:** `TERMINUS_SIGNATURE_HUB_INGEST_URL`.

**`TERMINUS_SIGNATURE_OUTBOUND_FLUSH_INTERVAL`**
- **Default:** `30`. **Type:** int (seconds).
- **Impact:** how often the background shipper flushes a batch to the Hub.
  Symptom: a longer interval means more batching and more delay before
  signatures reach the Hub; a shorter interval means more frequent small POSTs.
- **When to change:** tune it for Hub load versus freshness.
- **Interacts with:** `TERMINUS_SIGNATURE_OUTBOUND_BATCH_MAX`,
  `TERMINUS_SIGNATURE_OUTBOUND_BUFFER_MAX`.

**`TERMINUS_SIGNATURE_OUTBOUND_BATCH_MAX`**
- **Default:** `100`. **Type:** int.
- **Impact:** the maximum number of payloads sent in one POST. Symptom: if you
  generate more than this per flush, the backlog drains over successive flushes
  rather than in one POST.
- **When to change:** raise it for high signature volume.
- **Interacts with:** `TERMINUS_SIGNATURE_OUTBOUND_FLUSH_INTERVAL`,
  `TERMINUS_SIGNATURE_OUTBOUND_BUFFER_MAX`.

**`TERMINUS_SIGNATURE_OUTBOUND_BUFFER_MAX`**
- **Default:** `1000`. **Type:** int.
- **Impact:** the bounded in-memory buffer size. On overflow the OLDEST payload
  is dropped and counted. Symptom: if generation outpaces shipping (a slow or
  down Hub), `terminus_signature_outbound_dropped_total` climbs, telemetry is
  being shed to protect memory, and the request path is unaffected.
- **When to change:** raise it if you see drops and have memory headroom.
- **Interacts with:** `TERMINUS_SIGNATURE_OUTBOUND_FLUSH_INTERVAL`,
  `TERMINUS_SIGNATURE_OUTBOUND_BATCH_MAX`.

---

## 9. Velocity / sequence detection (F9)

Per-agent behavioral guardrail that detects a blind-extraction oracle: many
individually-allowed queries from one agent that together reconstruct
restricted data (row enumeration, or binary-search on an allowed aggregate).
It counts extraction-shaped reads (a SELECT with a WHERE) per agent, keyed by
the name-free query fingerprint. Opt-in; off by default. See SECURITY.md for
the model.

**`TERMINUS_VELOCITY_ENABLED`**
- **Default:** `false`. **Type:** bool.
- **Impact:** master switch for F9 per-agent velocity detection. When `false`,
  no velocity work runs. Symptom of off: no `velocity_anomaly` entries in
  `risk_reasons` or the audit chain, and `terminus_velocity_anomaly_total`
  never increments.
- **When to change:** turn it on to start observing extraction-shaped query
  volume per agent.
- **Interacts with:** `TERMINUS_VELOCITY_ENFORCE_ENABLED`,
  `TERMINUS_VELOCITY_WINDOW_SECONDS`, `TERMINUS_VELOCITY_THRESHOLD`.

**`TERMINUS_VELOCITY_ENFORCE_ENABLED`**
- **Default:** `false`. **Type:** bool.
- **Impact:** when `true`, a velocity anomaly escalates an otherwise-allowed
  query to a deny (`reason_code=velocity_anomaly`). It never overrides an
  existing deny. Symptom of `true` with an untuned threshold: legitimate
  high-volume analytics agents start getting denied for `velocity_anomaly`.
- **When to change:** enable it only after tuning the window and threshold
  against real traffic in observe mode.
- **Interacts with:** `TERMINUS_VELOCITY_ENABLED` (no effect without it).

**`TERMINUS_VELOCITY_WINDOW_SECONDS`**
- **Default:** `60`. **Type:** int (seconds), minimum `1`.
- **Impact:** the tumbling window length for counting same-fingerprint reads
  per agent.
- **When to change:** widen it to catch a slower extraction pattern; narrow it
  to react faster to a burst.
- **Interacts with:** `TERMINUS_VELOCITY_THRESHOLD`.

**`TERMINUS_VELOCITY_THRESHOLD`**
- **Default:** `30`. **Type:** int, minimum `1`.
- **Impact:** same-fingerprint reads from one agent within a window that trip
  the anomaly.
- **When to change:** raise it to reduce false positives from legitimate
  high-volume analytics; lower it to catch extraction sooner.
- **Interacts with:** `TERMINUS_VELOCITY_WINDOW_SECONDS`.

**`TERMINUS_VELOCITY_MAX_TRACKED`**
- **Default:** `10000`. **Type:** int, minimum `1`.
- **Impact:** LRU cap on tracked (agent, fingerprint) counters, bounding
  memory. Symptom of a cap set too low under high cardinality: the oldest
  counters are evicted and their counts reset, weakening detection.
- **When to change:** raise it if you have many distinct agent/fingerprint
  pairs and memory headroom.
- **Interacts with:** nothing functional.

---

## 10. MCP enforcement point (reference PEP for Postgres)

The MCP server sidecar that gates agent Postgres access through the decision
engine. A separate entrypoint (python -m terminus.mcp); the HTTP sidecar is
byte-for-byte unchanged when these are unset.

**`TERMINUS_MCP_ENABLED`**
- **Default:** `false`. **Type:** bool.
- **Impact:** master switch for MCP support. When `false`, the MCP server is
  not active. When `true`, the MCP server is operational. The HTTP sidecar is
  unaffected.
- **When to change:** set `true` to activate the MCP enforcement point.
- **Interacts with:** `TERMINUS_MCP_AGENT_ID`, `TERMINUS_MCP_POSTGRES_DSN`.

**`TERMINUS_MCP_AGENT_ID`**
- **Default:** empty string. **Type:** string.
- **Impact:** the agent identity this MCP server instance serves. Validated
  against the registry at startup. One server per agent identity for the
  reference PEP; per-session JWT via transport auth is a fast-follow.
- **When to change:** set it to the agent id this instance serves.
- **Interacts with:** `TERMINUS_AGENT_REGISTRY_PATH`.

**`TERMINUS_MCP_POSTGRES_DSN`**
- **Default:** empty string. **Type:** string (PostgreSQL connection string).
- **Impact:** the Postgres DSN the executor connects with. This is the ONLY
  place database credentials are set for the MCP server. Must be a valid,
  reachable connection string.
- **When to change:** set it to the target Postgres instance.
- **Interacts with:** nothing functional (independent of the HTTP sidecar).

**`TERMINUS_MCP_APPROVAL_RISK_THRESHOLD`**
- **Default:** `0.8`. **Type:** float (0.0 to 1.0).
- **Impact:** an allowed WRITE query whose parsed risk_score is >= this value
  triggers a human-approval break-glass flow instead of immediate execution.
  Policy and risk-driven (reuses the engine risk score), never a hardcoded
  operation set. Default 0.8 catches DELETE (0.9/1.0) and WHERE-less UPDATE
  (0.85); tune per deployment. Reads never require write-approval.
- **When to change:** lower it to require approval for more operations; raise
  it to require approval only for the highest-risk operations.
- **Interacts with:** nothing functional.

**`TERMINUS_MCP_APPROVAL_TIMEOUT_SECONDS`**
- **Default:** `300` (5 minutes). **Type:** int (> 0).
- **Impact:** the expiration window for a pending high-risk write waiting for
  approval. If approval is not received within this interval, the request is
  denied (fail-closed, never executes).
- **When to change:** adjust based on your approval response-time requirements.
- **Interacts with:** nothing functional.


**`TERMINUS_MCP_APPROVAL_MAX_HOLDS`**

- **Default:** `32`
- Bound on concurrently pending holds. At the bound, a new high-risk write is
  denied immediately (`reason_code="max_holds_exceeded"`, no structured
  `remediation` object) instead of being held (fail-closed availability; a
  hold flood cannot bypass policy). Watch `terminus_holds_active`.
- **Interacts with:** `TERMINUS_MCP_APPROVAL_TIMEOUT_SECONDS`.

---

## 11. Graduated autonomy (per-agent trust promotion)

Per-agent trust model: agents start in observe mode and may be promoted to
enforce mode by operators. When disabled, all agents are treated as enforce
(the default-deny baseline). See the capabilities doc for the full model.

**`TERMINUS_GRADUATED_AUTONOMY_ENABLED`**
- **Default:** `false`. **Type:** bool.
- **Impact:** master switch for per-agent trust levels. When `false`, the
  `trust_level` field in the registry is ignored and all agents are treated as
  enforce (the traditional default-deny posture). When `true`, each agent's
  registered `trust_level` (observe or enforce) controls access via the policy
  engine. Symptom of `false`: trust_level entries in agents.yaml have no effect.
- **When to change:** enable it once the graduated autonomy feature is
  operationally ready and agents have been evaluated in observe mode.
- **Interacts with:** `TERMINUS_AGENT_REGISTRY_PATH` (where trust_level is set).

---


---

## Cross-variable interaction map

The clusters where one variable's effect depends on another. Set them together.

- **Auth.** `JWT_SECRET` + `REQUIRE_AUTH` + `AGENT_REGISTRY_PATH`. Identity is
  only verifiable when the secret is real; the registry decides which verified
  `sub` values are accepted; `REQUIRE_AUTH` decides whether a token is mandatory.
- **Rate limiting.** `REDIS_URL` + `RATE_LIMIT_PER_MINUTE`. The budget means
  nothing if Redis is unreachable (fail-open).
- **Policy core.** `POLICY_PATH` + `SCHEMA_WHITELIST_PATH`. The whitelist is
  evaluated before policy rules; a table denied there never reaches the rules.
- **Signature data source.** `SIGNATURES_ENABLED` + `SIGNATURE_RISK_THRESHOLD`.
  These govern what gets emitted locally and, transitively, what outbound can
  ship.
- **Matching and inbound.** `SIGNATURE_MATCHING_ENABLED` +
  `SIGNATURE_ENFORCE_ENABLED` + `SIGNATURE_BUNDLE_SOURCE` +
  `SIGNATURE_BUNDLE_PUBLIC_KEY` + `SIGNATURE_POLL_INTERVAL` +
  `SIGNATURE_OVERRIDES_PATH`. Matching needs a source and a key to have anything
  to match; enforce needs matching on; overrides win locally.
- **Outbound.** `SIGNATURE_OUTBOUND_ENABLED` + `SIGNATURE_HUB_INGEST_URL` +
  `SIGNATURE_HUB_TOKEN` + the flush/batch/buffer trio. Outbound needs the URL to
  ship and `SIGNATURES_ENABLED` for a source.

## Must override in production

These have insecure or example defaults and should be set on every real
deployment:

- `TERMINUS_ENVIRONMENT` (`production` or `staging`, not the local `development`)
- `TERMINUS_JWT_SECRET` (a real random >= 32-byte secret)
- `TERMINUS_AUDIT_HMAC_KEY` (a real random >= 32-byte key, kept stable)
- `TERMINUS_POLICY_PATH`, `TERMINUS_SCHEMA_WHITELIST_PATH`,
  `TERMINUS_AGENT_REGISTRY_PATH` (your real files, not the bundled examples)
- `TERMINUS_REDIS_URL` (your Redis, unless using the bundled Docker stack)
- `TERMINUS_REQUIRE_AUTH=true` once all agents present JWTs

The two secrets are now **enforced**: outside `development`, Terminus refuses to
start if `TERMINUS_JWT_SECRET` or `TERMINUS_AUDIT_HMAC_KEY` is left at its shipped
default. The rest are still your responsibility to set (a `development` label or
example policy/whitelist paths do not block startup).
