# Terminus Operations Runbook

For the person who deploys Terminus and keeps it healthy. Configuration values
are in [docs/configuration.md](configuration.md); this document covers deploying,
smoke-testing, what every metric and log event means, and how to recover from the
failure modes you will actually hit.

## Orientation

Terminus is a sidecar that sits between your agents and your databases. It
intercepts each SQL statement on `POST /intercept`, validates it, and returns
allow (200) or deny (403 with machine-readable remediation). Its two operating
philosophies decide how it behaves under partial failure:

- **The core control fails closed.** Policy and the schema/column whitelists are
  default-deny. If the parser cannot understand a statement, it is denied.
- **The guardrails fail open.** Rate limiting and all signature telemetry are
  guardrails, not the core breaker. If Redis, the Hub, or a signature path
  fails, Terminus logs it and keeps validating SQL. Nothing about the signature
  subsystem can change a decision (beyond an intended enforce-mode escalation) or
  return a 500.

Keep that split in mind: a Redis or Hub outage is a degraded-telemetry event, not
a Terminus outage.

## Deploy

### Docker stack (recommended)

The bundled stack is Terminus + Redis + Prometheus + Grafana.

```bash
make up      # build and start all four services
make ps      # service status
make logs    # follow Terminus logs
make down    # stop everything
make rebuild # rebuild Terminus from current source and restart
```

| Service    | URL                   | Notes                                   |
|------------|-----------------------|-----------------------------------------|
| Terminus   | http://localhost:8000 | API + `/metrics`                        |
| Prometheus | http://localhost:9090 | scrapes `terminus:8000/metrics` every 15s |
| Grafana    | http://localhost:3000 | login `admin` / `admin`; dashboard auto-loaded |
| Redis      | localhost:6379        | rate-limit backend                      |

Docker-daemon permission gotcha on a fresh host: the user must be in the `docker`
group. If `make up` cannot reach the daemon, run `newgrp docker` (or re-login),
or prefix with `sg docker -c "..."`.

### Standalone (no Docker)

```bash
PYTHONPATH=src uv run uvicorn terminus.main:app --host 0.0.0.0 --port 8000
```

Rate limiting needs Redis; without it the limiter fails open (logs
`rate_limiter_unavailable` at startup) and SQL validation still runs.

### Before going to production

Set the must-override variables from
[docs/configuration.md](configuration.md#must-override-in-production):
`TERMINUS_JWT_SECRET`, `TERMINUS_AUDIT_HMAC_KEY`, your real
`TERMINUS_POLICY_PATH` / `TERMINUS_SCHEMA_WHITELIST_PATH` /
`TERMINUS_AGENT_REGISTRY_PATH`, `TERMINUS_REDIS_URL`, and
`TERMINUS_REQUIRE_AUTH=true` once all agents present JWTs.

If your database is not PostgreSQL, also set `TERMINUS_SQL_DIALECT` to its
dialect (for example `snowflake`, `bigquery`, `mysql`, `duckdb`) so identifier
matching for the schema whitelist and policy rules follows that database's
case-folding rules. Leaving it empty assumes Postgres/generic lowercase
folding; on a dialect that folds unquoted identifiers differently (Snowflake
folds to UPPERCASE), an unset `TERMINUS_SQL_DIALECT` can mismatch the
whitelist against real queries.

### Worker model

Run exactly **one worker per process**. The audit HMAC chain, velocity
trackers, and signature store are per-process globals; more than one worker
silently splits them into independent, interleaved segments (the audit
verifier reads this as `broken_link`/`anchor_mismatch`) and multiplies the
effective rate/velocity thresholds. A boot-time guard
(`terminus.config.worker_guard`) checks for this before the app finishes
starting:

- **development:** a detected worker count above 1 logs `multi_worker_detected`
  (warning) and boots anyway, so local experiments are not blocked.
- **staging/production:** the same condition raises `RuntimeError` and aborts
  startup: `refusing to start in environment=... with N workers (detected via
  ...): the audit HMAC chain, velocity trackers, signature store are
  per-process and silently fragment under multiple workers, which breaks
  audit-chain verification. Run ONE worker per container/pod and scale
  horizontally, or set TERMINUS_ALLOW_UNSAFE_MULTI_WORKER=true to boot anyway
  (unsafe).`
- **`TERMINUS_ALLOW_UNSAFE_MULTI_WORKER=true`** boots anywhere regardless of
  environment, logging `multi_worker_override_unsafe` (warning) instead of
  raising. This is a named escape hatch, not a fix: it voids the audit and
  velocity guarantees.

Detection is positive-evidence only, in this precedence order: `TERMINUS_WORKER_COUNT`
(operator attestation, authoritative when set) beats `WEB_CONCURRENCY` (honored
as a read-only operational input, the Heroku/gunicorn convention some
platforms set for you) beats parsing the parent process's command line for
`--workers`/`-w` (uvicorn/gunicorn). When none of these yield a count, the
guard logs `worker_count_unknown` outside development and boots: refusing to
start on an unknown count would be an availability self-DoS on platforms this
guard cannot introspect (non-Linux, exotic process managers).

Scale horizontally instead of with worker flags: one worker per
container/pod, N containers/pods behind your load balancer. The bundled
shared Redis backs only the rate limiter across replicas; it does not share
the audit chain, velocity trackers, or signature store. Each replica keeps its
own audit chain and needs its own `terminus_audit_checkpoint` head captured
independently (see [Key log events](#key-log-events) and
[docs/audit-to-siem.md](audit-to-siem.md)). Redis-backed velocity/rate-limit
state shared across replicas is named backlog, not yet implemented.

## Hardening for production

The Docker image is multi-stage and non-root by default (see
[SECURITY.md](../SECURITY.md#container-posture)), but the image alone is not a
production posture. Before pointing a real deployment at Terminus:

- **Real secrets.** `TERMINUS_JWT_SECRET` and `TERMINUS_AUDIT_HMAC_KEY` must be
  genuine, randomly generated values of at least 32 bytes, not the shipped
  defaults (`assert_production_secrets` refuses to boot on the default in
  `production`/`staging`, but nothing stops a weak-but-different secret).
- **`TERMINUS_ENVIRONMENT=production`.** This is what turns on the secret
  guard, the multi-worker guard, and the hardened defaults documented in
  [docs/configuration.md](configuration.md). Do not run production traffic
  with `TERMINUS_ENVIRONMENT=development`.
- **One worker per container.** Set `TERMINUS_WORKER_COUNT=1` as an explicit
  operator attestation (see [Worker model](#worker-model) above); scale by
  running more containers/pods, never `--workers`/`-w` in one process.
- **Network-restrict `/metrics`.** It is unauthenticated by design (Prometheus
  scrape convention); put it behind a proxy or network policy that only your
  scraper can reach, not the public internet.
- **Redis on the internal network, with a password.** Bind Redis so only
  Terminus can reach it and set `requirepass`; the bundled
  `docker-compose.yml` is a local/demo stack and does neither.
- **Rotate the Grafana admin credentials.** The bundled stack ships
  `admin`/`admin`; change it (or disable Grafana entirely) before exposing the
  stack beyond localhost.
- **JWT posture.** `TERMINUS_JWT_REQUIRE_EXP` defaults to `true` (every agent
  JWT must carry an expiry); also consider setting
  `TERMINUS_JWT_MAX_LIFETIME_SECONDS` to cap how long a minted token can live,
  even one presented with a distant `exp`.
- **Capture the audit checkpoint head into your SIEM.** Each replica keeps its
  own signed audit chain; ship `terminus_audit_checkpoint` events off-box so
  chain verification survives container recycling. See
  [docs/audit-to-siem.md](audit-to-siem.md).
- **Docs surface disabled.** `TERMINUS_DISABLE_DOCS` should be `true` in
  production so `/docs`, `/redoc`, and `/openapi.json` are not exposed.
- **Verify non-root.** `docker run --rm <image> id -u` must print a non-zero
  uid. This is exactly what `make docker-smoke` checks.

**Deploy cycle: build, smoke, then ship.** CI runs `make docker-smoke` as a
dedicated `Container` job on every push and pull request to main, alongside
Lint, Test, and Type Check. You should also run `make docker-smoke` as the
image-level check before every local deploy: it builds the image fresh, asserts
the container runs as non-root, and asserts `/health` returns 200.

## Smoke test (no Docker required)

```bash
# Health
curl -s http://localhost:8000/health
# -> {"status":"ok","service":"terminus","environment":"production"}

# Allowed query (200)
curl -s -X POST http://localhost:8000/intercept -H 'Content-Type: application/json' \
  -d '{"sql":"SELECT id FROM public.users WHERE id=1","agent_id":"analytics_agent_42"}'
# -> {"decision":"allow", ...}

# Denied query (403 + remediation header)
curl -si -X POST http://localhost:8000/intercept -H 'Content-Type: application/json' \
  -d '{"sql":"DROP TABLE public.users","agent_id":"analytics_agent_42"}' | head -20
# -> HTTP/1.1 403 ... X-Terminus-Remediation: ...

# Metrics populated
curl -s http://localhost:8000/metrics | grep ^terminus_
```

What good looks like: `/health` returns 200, the allow/deny decisions are
correct, the deny carries an `X-Terminus-Remediation` header, and `/metrics`
shows `terminus_requests_total` with `reason` labels plus `terminus_build_info`.

## Endpoints

| Method | Path         | Purpose                              |
|--------|--------------|--------------------------------------|
| GET    | `/health`    | liveness; returns status + environment |
| GET    | `/metrics`   | Prometheus exposition (text)         |
| GET    | `/`          | service banner + links               |
| POST   | `/intercept` | validate one SQL statement           |

Raw SQL is never echoed in any response, header, or log; only a keyed
HMAC-SHA256 digest (`sql_sha256`) is recorded.

## Metrics catalog

What each series means and what to watch. Prometheus counters do not appear until
first incremented, so a fresh process may not export every series yet.

| Metric | Type | Labels | What it means / what to watch |
|--------|------|--------|-------------------------------|
| `terminus_requests_total` | counter | `action`, `reason`, `operation` | Every decision. `action` is allow/deny; `reason` is a low-cardinality code (see reason codes below). A rising deny rate by `reason` tells you *why* traffic is being blocked. |
| `terminus_smuggling_attempts_total` | counter | `reason` | Queries the parser flagged with a smuggling pattern (comment obfuscation, hidden subquery, injection functions). A spike means someone is probing. |
| `terminus_parser_latency_seconds` | histogram | none | Parse + security-analysis time. Watch p99 against your latency budget (target < 2 ms). A rising p99 is the first sign of pathological queries. |
| `terminus_active_agents` | gauge | none | Distinct agent ids seen this process. A sudden jump can indicate a new (or spoofing) caller. |
| `terminus_build_info` | gauge | `version`, `environment` | Always 1; use it to confirm which build/environment a series came from. |
| `terminus_auth_events_total` | counter | `result` | JWT auth outcomes: `verified`, `rejected`, `legacy`. Rising `rejected` means bad/expired/unknown tokens; nonzero `legacy` means callers are still using the self-asserted path (you have not finished the JWT migration). |
| `terminus_signature_matches_total` | counter | `mode`, `severity` | Known-bad signature matches. `mode=enforce` matches escalated an allow to a deny; `mode=observe` only annotated. A jump means the corpus is catching things locally. |
| `terminus_signature_version_skew_total` | counter | none | Bundle records skipped because their `fingerprint_version` did not match this sidecar. Climbing after a fingerprint-algorithm change is expected; climbing otherwise means a misformatted bundle. |
| `terminus_signature_outbound_sent_total` | counter | none | Payloads successfully POSTed to the Hub. Flat while outbound is enabled means the Hub is unreachable. |
| `terminus_signature_outbound_failed_total` | counter | none | Payloads dropped after all POST retries failed. Sustained increase = the Hub is down or rejecting. |
| `terminus_signature_outbound_dropped_total` | counter | none | Payloads dropped by buffer overflow (generation outpacing shipping). Climbing = the Hub is slow/down and telemetry is being shed to protect memory. |
| `terminus_signature_outbound_guard_tripped_total` | counter | none | Signatures the privacy guard refused to ship. Should be ~0; any nonzero value warrants investigation (a bug would otherwise have leaked). |
| `terminus_signature_emitter_errors_total` | counter | `leg` | An emitter leg raised during emit. Nonzero on `leg=OutboundEmitter` means the outbound enqueue path is erroring; the log leg keeps working. |
| `terminus_config_reload_total` | counter | `result` | Governance config reload attempts by result: applied (successful swap), unchanged (files not modified), failed (bad config rejected, last-known-good retained). Rising `failed` means a bad config push was rejected and last-known-good retained. |
| `terminus_config_last_reload_timestamp` | gauge | none | Epoch seconds of the last successful governance config reload. Use for staleness: how long since the last successful apply. |
| `terminus_rate_limiter_unavailable_total` | counter | none | Rate limiter unavailable, skipped, or erroring (Redis health). Climbs per skipped request while Redis is down. Nonzero means per-agent throttling is off (fail-open); the core breaker is unaffected. |
| `terminus_signature_bundle_update_failed_total` | counter | none | Failed inbound signed signature-bundle updates. The matcher keeps last-known-good, so detection continues on existing signatures but new threat intel is not applied. Threat-intel path, not auth. |
| `terminus_would_deny_total` | counter | `reason_code`, `operation` | Graduated autonomy only: an observe-trust agent's request that would have been denied under enforce, but was softened to an allow. `reason_code` is the original deny code (e.g. `policy_rule`, `schema_whitelist`); use this to see what a promotion to enforce would actually start blocking, before you flip the trust level. |

The provisioned Grafana dashboard charts request rate by decision/reason, parser
latency p50/p95/p99, smuggling attempts, and active agents.

## Key log events

Structured (key=value / JSON) events worth recognizing at 2am. Raw SQL never
appears; identifiers and literals never appear in signature events.

| Event | Level | Fires when | What it means / what to do |
|-------|-------|-----------|----------------------------|
| `terminus_intercept_decision` | info | every decision | The tamper-evident audit event (HMAC-chained). Carries decision, reason_code, operation, tables, risk, a keyed-HMAC `sql_sha256` digest, and a monotonic `sequence` (HMAC-signed, checked for continuity on verification). This is your forensic record. |
| `terminus_audit_checkpoint` | info | every `TERMINUS_AUDIT_CHECKPOINT_INTERVAL` decision events, and once on graceful shutdown | A distinct, itself-HMAC-signed out-of-band checkpoint of the current chain head (`boot_id`, `sequence`, `head_signature`, `checkpoint_time`). Capture it outside the mutable audit store (an external SIEM) so a chain can later be checked against it for tail truncation; see [docs/audit-to-siem.md](audit-to-siem.md). |
| `rate_limiter_initialized` | info | startup, Redis reachable | Rate limiting is active. |
| `rate_limiter_unavailable` | warning | startup, Redis unreachable | Rate limiting is OFF (fail-open); SQL validation still runs. Fix Redis or accept no throttling. |
| `rate_limit_skipped` | warning | per request, limiter not initialized | A request bypassed the limit because the limiter is down. Same root cause as above. |
| `rate_limit_error` | warning | per request | The limiter itself errored and failed open. Investigate if frequent. |
| `auth_rejected` | warning | invalid/expired/wrong-alg/unknown-sub token | A 401 was returned. Expected during token rollout; a spike means clients are misconfigured. |
| `auth_legacy_unauthenticated` | warning | no token, `REQUIRE_AUTH=false` | A caller used the self-asserted path. You have not finished the JWT migration; flip `REQUIRE_AUTH=true` when ready. |
| `agent_registry_missing` / `agent_registry_unparseable` | warning | startup/load | The agent registry file is missing or invalid; verified tokens will be rejected until fixed. |
| `signature_bundle_applied` | info | inbound bundle verified + swapped | Normal update. Includes the bundle id and record count. |
| `signature_bundle_update_failed` | error | fetch/verify/parse failure | A bundle was rejected; the store kept last-known-good. Check the Hub URL, the pinned public key (rotation?), and network. See failure modes below. |
| `signature_outbound_post_failed` | warning | outbound POST exhausted retries | A batch was dropped (best-effort). Correlates with `..._failed_total`. The Hub is down or rejecting. |
| `signature_privacy_guard_tripped` / `signature_outbound_guard_tripped` | warning | a signature failed the privacy vocabulary check | Fail-closed: the signature was dropped, not emitted/shipped. Should never happen in normal operation; treat as a code bug to report. |
| `signature_emit_failed` / `signature_match_failed` | warning | a bug in the signature path | Caught and swallowed so the request is unaffected; the request still got its correct decision. Investigate the named exception class. |
| `suggest_rewrite_failed` | warning | a safe-rewrite candidate could not be verified | No rewrite was attached (fail-safe). Harmless. |
| `config_reloaded` | info | a new governance config was applied | Normal hot-reload event. Includes which file(s) changed. |
| `config_reload_failed` | error | a reload was rejected, last-known-good retained | A bad config push was rejected. Investigate the named error; no restart needed, the old config is still active. |
| `policy_limit_not_enforced` | warning | boot or applied hot-reload, a policy rule sets `limits.max_queries_per_minute` | Fields: `policy_id`, `limit`. The field is parsed but not enforced; only the global `TERMINUS_RATE_LIMIT_PER_MINUTE` is active. Not a bug, just don't mistake the config for a working per-policy rate limit. |
| `trust_change_audit_failed` | error | a reload applied but the trust-change audit event failed to emit | Fire-and-forget: the config reload already succeeded and is not rolled back, and the failed audit emission is dropped, not retried. The new trust level is active even though this one promotion/demotion event is missing from the chain; investigate the named error and cross-check `agents.yaml` history for provenance. |
| `multi_worker_detected` | warning | startup, `development`, more than one worker detected | Boots anyway. The audit chain, velocity trackers, and signature store will fragment across workers; harmless for local experiments, fix before deploying. |
| `multi_worker_override_unsafe` | warning | startup, `TERMINUS_ALLOW_UNSAFE_MULTI_WORKER=true`, more than one worker detected | Boots anyway in any environment. The named escape hatch: audit and velocity guarantees are void until you drop back to one worker. |
| `worker_count_unknown` | info | startup, `staging`/`production`, no worker-count signal found | Assumes one worker and boots. Set `TERMINUS_WORKER_COUNT` to attest explicitly if you are unsure this platform's detection actually works. |

Two additional failure reasons, `sequence_gap` and `tail_truncation`, can surface
from offline audit-chain verification (`verify_audit_chain`; see
[docs/capabilities/audit.md](capabilities/audit.md)), not from a live decision.
They are audit-chain integrity failures, distinct from the policy `reason_code`
table below, and are not policy decisions.

## Why a query was denied (reason codes)

The `reason_code` on a 403 (and the `reason` metric label) tells you which gate
denied a query:

| reason_code | Meaning |
|-------------|---------|
| `schema_whitelist` | references a table not on the whitelist |
| `column_whitelist` | selects a column not allowed on a column-restricted table (or a wildcard/unqualified column on one) |
| `policy_rule` | matched a policy rule whose action is deny |
| `risk_threshold` | exceeded a policy rule's `max_destructive_risk_score` |
| `signature_match` | matched a known-bad threat-intelligence signature (enforce mode) |
| `invalid_sql` | could not be parsed safely |
| `oversize_sql` | SQL longer than `TERMINUS_MAX_SQL_LENGTH`, denied before parsing to bound event-loop cost |
| `multi_statement` | multiple statements in one request (blocked by default) |
| `injection_function` | called an injection or time-based SQL function (`pg_sleep`, `benchmark`, ...) on the allow path, with `TERMINUS_ENFORCE_INJECTION_BLOCK=true` |
| `nested_write` | a data-modifying operation (INSERT, UPDATE, DELETE, MERGE) is nested inside a CTE, hidden from the top-level operation the policy rules would otherwise evaluate |
| `default` | no rule allowed it; the default-deny action applied |

A `429` (not a reason_code) is the per-agent rate limit, not a policy decision.

## Failure modes and recovery

- **Redis is down.** Symptom: `rate_limiter_unavailable` at startup,
  `rate_limit_skipped` per request, no client ever gets a 429. Effect: rate
  limiting is off; core SQL validation is unaffected (fail-open by design).
  Recovery: restore Redis and restart, or accept no throttling temporarily.
- **The Hub is down or slow (inbound).** Symptom:
  `signature_bundle_update_failed` (error) and the matcher store stops updating.
  Effect: the sidecar keeps matching on the last-known-good set; nothing breaks.
  Recovery: restore the Hub/source; the next poll applies a fresh bundle.
- **The Hub is down (outbound).** Symptom: `signature_outbound_post_failed`,
  `..._failed_total` and then `..._dropped_total` climbing. Effect: telemetry is
  buffered, retried, then shed oldest-first to protect memory; the request path
  is unaffected. Recovery: restore the Hub; raise
  `TERMINUS_SIGNATURE_OUTBOUND_BUFFER_MAX` if you want a deeper buffer.
- **A rotated or wrong bundle public key.** Symptom: persistent
  `signature_bundle_update_failed` even though the source is reachable. Effect:
  bundles are rejected fail-closed; the store keeps last-known-good, so updates
  quietly stop without an obvious outage. Recovery: update
  `TERMINUS_SIGNATURE_BUNDLE_PUBLIC_KEY` to the current key.
- **A signature false positive denies legitimate traffic.** Symptom: a known
  query starts returning 403 `signature_match`. Recovery: disable or downgrade
  that `signature_id` in the local overrides file
  (`TERMINUS_SIGNATURE_OVERRIDES_PATH`); local always wins, no bundle wait. Or,
  globally, set `TERMINUS_SIGNATURE_ENFORCE_ENABLED=false` to drop back to
  observe-only while you investigate.
- **An injection-function false positive denies legitimate traffic.** Symptom:
  a known query starts returning 403 `injection_function`. Recovery: set
  `TERMINUS_ENFORCE_INJECTION_BLOCK=false` to drop back to observe-only while
  you investigate; the signal still appears in `risk_reasons` and the
  smuggling metric.
- **Insecure secret defaults left in place.** Outside `development`, this now
  fails fast: startup raises and the process refuses to boot when
  `TERMINUS_AUDIT_HMAC_KEY` or `TERMINUS_JWT_SECRET` is still the shipped default
  (the audit chain would be forgeable and any agent identity spoofable).
  Recovery: set real >= 32-byte secrets and restart; see
  [docs/configuration.md](configuration.md). In `development` (the bundled Docker
  stack) the example secrets are permitted and there is no error.
- **Malformed or oversized SQL.** Symptom: 403 `deny` with `reason_code`
  `invalid_sql` (unknown dialect, unparseable, or pathological nesting) or
  `oversize_sql` (over `TERMINUS_MAX_SQL_LENGTH`). These now fail closed
  as a deny rather than a 500; a `sql` field over 128 KiB is a `422`, and a
  whole request body over `TERMINUS_MAX_REQUEST_BODY_BYTES` (default 256 KiB) is
  rejected as `413` before parsing. No action needed unless a legitimate query is
  affected, in which case raise `TERMINUS_MAX_SQL_LENGTH` after load-testing.
- **Parser latency p99 rising.** Symptom: `terminus_parser_latency_seconds` p99
  drifting up. Effect: added per-query latency. Likely cause: unusually large or
  pathological SQL. Investigate the offending agent; the parser cost dominates
  the request, so this is your earliest performance signal.

## Alerting

Prometheus alerting rules for the bundled monitoring stack live in
`prometheus/alerts.yml`. The rules file is registered in `prometheus.yml` via
`rule_files: [/etc/prometheus/rules/*.yml]` and is bind-mounted into the
Prometheus container by `docker-compose.yml`.

| Alert | Metric used | Threshold / for | Severity |
|-------|-------------|-----------------|----------|
| `TerminusDown` | `up{job="terminus"}` | == 0 / 1m | critical |
| `TerminusDenyRateHigh` | `terminus_requests_total{action="deny"}` / total | > 25% of all requests / 5m | warning |
| `TerminusParserLatencyHigh` | `terminus_parser_latency_seconds` (p99) | > 2 ms / 5m | warning |
| `TerminusSmugglingAttemptsDetected` | `terminus_smuggling_attempts_total` | > 0.1/min rate / 2m | critical |
| `TerminusSignatureOutboundFailing` | `terminus_signature_outbound_failed_total` | any rate > 0 / 10m | warning |
| `TerminusSignatureOutboundDropped` | `terminus_signature_outbound_dropped_total` | any rate > 0 / 5m | warning |
| `TerminusConfigReloadFailing` | `terminus_config_reload_total{result="failed"}` | any rate > 0 / 5m | warning |
| `TerminusConfigStale` | `terminus_config_last_reload_timestamp` | > 1 h since last apply (only when reload is active) / 5m | warning |
| `TerminusRateLimiterUnavailable` | `terminus_rate_limiter_unavailable_total` | any rate > 0 / 5m | warning |
| `TerminusSignatureBundleUpdateFailed` | `terminus_signature_bundle_update_failed_total` | any rate > 0 / 10m | warning |

To validate the rules file outside Docker:

```bash
promtool check rules prometheus/alerts.yml
```

`promtool` ships inside the `prom/prometheus` image; run it via:

```bash
docker run --rm -v "$(pwd)/prometheus:/rules:ro" prom/prometheus:latest \
  promtool check rules /rules/alerts.yml
```

Signals that are log-only (no metric exists, no alertable series): `rate_limiter_unavailable`,
`rate_limit_skipped`, `rate_limit_error`, and individual signature bundle update
failures (`signature_bundle_update_failed` log event). These appear in
structured logs but are not exposed as Prometheus counters. If alerting on
Redis unavailability or bundle fetch failures becomes a priority, dedicated
counters would need to be added to `src/terminus/observability/metrics.py`.

## Velocity detection (F9) rollout

F9 detects a blind-extraction oracle: many individually-allowed queries from
one agent that together reconstruct restricted data (row enumeration, or
binary-search on an allowed aggregate). It counts extraction-shaped reads (a
SELECT with a WHERE) per agent, keyed by the name-free query fingerprint.

Roll out crawl, walk, run:
1. Turn on observe: set `TERMINUS_VELOCITY_ENABLED=true`. Anomalies appear as
   `velocity_anomaly` in `risk_reasons` and the audit chain, and increment
   `terminus_velocity_anomaly_total`. Nothing is blocked.
2. Tune `TERMINUS_VELOCITY_WINDOW_SECONDS` and `TERMINUS_VELOCITY_THRESHOLD`
   against real traffic until legitimate high-volume analytics no longer trips
   it.
3. Turn on enforce: set `TERMINUS_VELOCITY_ENFORCE_ENABLED=true` to deny on
   anomaly.

Limitations (by design in v1): state is in-process, so a multi-replica
deployment counts each replica separately; the signal is velocity, so a
low-and-slow attacker pacing under the threshold is not caught. These are
documented seams for a later revision, not blocking a single-or-low-replica
pilot. Velocity ENFORCE is applied only to JWT-authenticated agents:
unauthenticated or self-asserted traffic is observe-only, still flagged with
`velocity_anomaly` but never denied. This prevents a spoofed or anonymous
identity from driving a cross-agent denial (an attacker cannot spoof a
victim's agent id, or flood the shared "unknown" bucket, to get someone
else's legitimate queries denied).

## What good looks like

A healthy production Terminus: `/health` 200; `terminus_build_info` shows your
expected version/environment; `rate_limiter_initialized` at startup (not
`unavailable`); `terminus_auth_events_total{result="legacy"}` at 0 once migration
is done; the deny rate by `reason` stable and explainable; parser p99 well under
2 ms; and, if signatures are enabled, `signature_bundle_applied` on schedule with
`..._outbound_failed_total` / `..._dropped_total` flat.
