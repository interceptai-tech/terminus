# PROJECT.md — Terminus, in depth

> **What this file is:** the architecture and orientation guide a senior engineer
> would hand a new hire (human or AI). Read this first for *how the system is
> shaped and why*. For *known weaknesses* see `GAPS.md`. For *how to operate the
> repo day to day* (commands, conventions, gotchas) see `CLAUDE.md`.
>
> The project's non-negotiable principles and contribution workflow are preserved
> verbatim at the bottom of this file (see "Project Charter").

---

## 1. What Terminus is, in plain language

Terminus is a **circuit breaker for autonomous AI agents that have database
access**. It is a small FastAPI web service (a "sidecar") that you deploy next to
your database. Before an agent runs a SQL statement, it sends that statement to
Terminus's `POST /intercept` endpoint. Terminus parses the SQL, checks it against
security policy, and answers **allow** (HTTP 200) or **deny** (HTTP 403) with
structured, machine-readable feedback so the agent can correct itself.

The mental model from IT ops: it is a **layer-7 firewall + audit appliance for
SQL**. It sits at the data plane, where a syntactically valid `DROP TABLE` or an
unbounded `DELETE` actually does damage, because prompt-level guardrails on the
agent side are not enforceable once the model can emit real SQL.

### The single most important thing to understand

**Terminus is a decision API, not a database proxy.** It never connects to a
database, never executes SQL, and never sees query results. It receives SQL text,
returns a verdict, and trusts the caller to honor that verdict. There is no data
plane inside Terminus — the `tables`/`columns`/`operation` it reports all come
from *parsing the SQL string*, never from a live schema. This is why:

- It can be fast (~0.5 ms in-process p99) and stateless-per-query.
- Wildcards (`SELECT *`) and no-column-list `INSERT`s on column-restricted tables
  are **denied**, not expanded — Terminus has no schema to expand them against.
- The security boundary depends on the caller *actually calling Terminus and
  obeying it*. That integration discipline is the customer's responsibility; the
  sidecar cannot enforce that it is in the path.

### Who it's for

Platform / security teams giving production DB write access to autonomous agent
frameworks (LangGraph, CrewAI, custom multi-agent systems). Built by **InterceptAI**
(interceptai.tech). Positioned for SOC 2-conscious enterprises (see
`docs/security-compliance-spec.md`).

---

## 2. Tech stack and why each piece is here

| Piece | Role | Why this choice |
|---|---|---|
| **Python 3.11+** (CI + Docker run 3.13) | Language | Ecosystem for `sqlglot`; ops-team readability over cleverness (Charter principle 8). |
| **FastAPI** + **uvicorn[standard]** | HTTP + ASGI server | Async, typed, Pydantic-native. Lifespan hook warms caches and manages Redis. |
| **sqlglot** (>=25) | SQL parser / AST | The heart of the product. AST inspection (not regex/substring) is what makes smuggling detection sound: a *function node* `pg_sleep(...)` is caught while a *type* `varchar(255)` is not. Also does dialect-aware identifier normalization. |
| **Pydantic v2** + **pydantic-settings** | Models + config | Every wire/config object is a validated model. Settings come only from `TERMINUS_*` env vars (`.env` loading is deliberately disabled). |
| **structlog** | Logging | JSON structured logs; carries the audit chain. `key=value`/JSON is required by the ops style. |
| **Redis** + **fastapi-limiter (pinned 0.1.5)** | Per-agent rate limiting | Rate limiting is a *guardrail*, so it is the one control allowed to fail **open**. Pin is load-bearing — see gotchas. |
| **prometheus-client** + **Grafana** | Observability | `/metrics` exposition; a provisioned dashboard ships in `grafana/provisioning/`. Labels are deliberately low-cardinality. |
| **pyjwt** (HS256) | Agent identity | Verified JWT `sub` is the trusted `agent_id`, overriding any self-asserted header. |
| **cryptography** (>=42, Ed25519) | Signed threat-signature bundles | Sidecar pins a public key and verifies bundles it can never forge (verify-before-trust). |
| **uv** + **hatchling** | Dep/build tooling | `uv` for fast installs; `src/` layout packaged by hatchling. |

Dev/quality gates: **ruff**, **black**, **isort**, **mypy --strict**, **pytest**
(+ pytest-asyncio, pytest-benchmark). All enforced in CI.

---

## 3. Architecture and data flow

Terminus is a sidecar: deploy it close to the DB (same VPC / k8s cluster) and
route agent SQL through it.

```
                                 ┌──────────────────────── Terminus sidecar ────────────────────────┐
  AI agent                       │                                                                   │
  ──POST /intercept──▶  authenticate(JWT) ─▶ rate limit ─▶ parse(sqlglot, off-loop) ─▶ policy.evaluate│──▶ 200 allow
  {sql, agent_id,      │  (auth/)          (interceptor/)   (parser/)                 (policy/)        │
   dialect, metadata}  │      │                  │              │                        │            │──▶ 403 deny
                       │      │                  │              │                        │            │    + X-Terminus-Remediation
                       │      ▼                  ▼              ▼                        ▼            │
                       │  sets trusted     fail-open if    fail-closed:          default-DENY;       │
                       │  agent_id from    Redis down      oversize/invalid/      whitelist ▶ column ▶│
                       │  verified sub                     multi-stmt ⇒ deny      injection ▶ nested- │
                       │                                                          write ▶ rules       │
                       │                                                                              │
                       │  ── post-decision, all fail-safe (can only TIGHTEN, never 500) ──            │
                       │   signature match (allow→deny)  ·  velocity/sequence check (allow→deny)      │
                       │                                                                              │
                       │   remediation ─▶ Prometheus metrics ─▶ HMAC audit chain ─▶ signature emit    │
                       └───────────────────┬───────────────────────────┬──────────────────┬──────────┘
                                           ▼                           ▼                  ▼
                                    /metrics ─▶ Prometheus ─▶ Grafana   audit log      terminus.signature
                                                                       (HMAC chain)    stream (name-free)
                                                                                            │ opt-in
                                                                                            ▼
                                                                                    Hub (Ed25519 bundles
                                                                                    in ⇄ telemetry out)
```

### The evaluation order inside `/intercept` (this order is a security invariant)

`src/terminus/interceptor/router.py :: intercept()` orchestrates, in this order:

1. **`authenticate`** (FastAPI dependency, `auth/dependency.py`). Verifies a Bearer
   JWT (HS256, alg-pinned). A valid token's `sub` is set on
   `request.state.trusted_agent_id` and **overrides** any `X-Agent-ID` /
   body `agent_id` everywhere downstream. Invalid/expired/unknown-sub → 401 always.
   Missing token → 401 only if `TERMINUS_REQUIRE_AUTH=true`; otherwise the
   permissive "legacy" path (self-asserted id, logged + counted).
2. **`enforce_rate_limit`** (dependency). Per-agent, Redis-backed. **Fails open**:
   if Redis is down or the limiter errors, the request proceeds (guardrail, not
   the core control). A real 429 is intentional and propagates.
3. **Parse** (`parser/sql_parser.py :: parse_sql`) — run via `asyncio.to_thread`
   so the CPU-bound AST walk never blocks the event loop. Size-capped *before*
   parsing (`max_sql_length`, default 16 KiB) so a pathological statement can't
   stall the loop. Fail-closed: oversize / unknown-dialect / unparseable / deep
   nesting / any internal error → an `INVALID` `ParsedSQL` (an audited deny),
   never a 500.
4. **`policy_engine.evaluate`** (`policy/policy_engine.py`) — the core decision,
   itself ordered fail-closed:
   `invalid → multi-statement → schema whitelist → column allowlist → injection
   function → nested writes (writable CTE) → priority-ordered rules → default
   action (deny)`.
5. **Fingerprint once** — if signature matching or velocity is enabled, compute
   the one name-free `query_fingerprint` both consumers reuse. Any error degrades
   to "no signal" (never changes the decision).
6. **Signature match** (Phase 2A) — an enforce-mode match can escalate an *allow*
   to a *deny* (`reason_code=signature_match`). Floor-and-tighten: never downgrades
   a deny.
7. **Velocity / sequence check** (F9) — behavioral guardrail for blind-extraction
   oracles. Observe by default; under enforce it can escalate an *allow* to a
   *deny*, **only for a JWT-authenticated identity** (spoofable ids are observe-only
   to prevent cross-agent DoS).
8. **`suggest_rewrite`** (off-loop) — only on a wildcard-column deny: generates a
   safe column-enumerated rewrite, **re-validates it through the full engine for
   the same agent**, and attaches it only if it would be allowed.
9. **Remediation → metrics → audit → signature emit**. Emission is telemetry:
   wrapped so a bug there can never change the decision or 500 the request.

Everything from step 5 onward is **post-decision and fail-safe**: it can only
tighten an allow into a deny or annotate; it can never loosen a deny and never
crash the request.

### Component map (`src/terminus/`)

| Package | Responsibility | Load-bearing? |
|---|---|---|
| `main.py` | App factory, lifespan (Redis, cache warming, poll loops), `/`, `/health`, `/metrics`, body-size + context middleware, **boot-time secret + dialect guards**. | **Yes** |
| `interceptor/router.py` | `POST /intercept`; the orchestration above; `_SafeRateLimiter`. | **Yes** |
| `parser/sql_parser.py` | sqlglot parse, table/column extraction, smuggling flags, risk score, dialect normalization, cost/fail-closed bounds. | **Yes (most subtle code in the repo)** |
| `policy/policy_engine.py` | Policy + schema/column whitelist models and evaluation; `suggest_rewrite`. | **Yes** |
| `config/settings.py` | `TERMINUS_*` settings; `assert_production_secrets`, `assert_known_dialect`, ≥32-byte secret validator. | **Yes** |
| `config/governance.py` | Immutable `GovernanceSnapshot` (policy+whitelist+registry) with atomic swap + GitOps hot-reload + last-known-good. `get_policy_engine`/`get_registry` read from here. | **Yes** |
| `audit/audit_logger.py` | HMAC-SHA256 chained audit events, keyed `sql_digest`, sequence counter, signed checkpoints. | **Yes** |
| `audit/verify.py` | Independent chain verifier (signature, linkage, sequence, tail-truncation). | Yes (forensics) |
| `auth/` | JWT verify/mint (`tokens.py`), FastAPI `authenticate` dep, agent registry, `issue` CLI (`__main__.py`). | Yes |
| `remediation/remediation.py` | Builds agent-facing suggestions + `X-Terminus-Remediation` header value. | Yes |
| `signature/` (14 modules) | The "flywheel": name-free extraction (`facts.py` chokepoint), `signature.py` fingerprint, `gate.py`, `store.py`, `matcher.py`, `verify.py` (Ed25519), `update_client.py` (inbound bundles), `outbound.py` (opt-in telemetry), `emitter.py` (composite). | Yes (mostly opt-in) |
| `velocity/` | Per-agent tumbling-window extraction-oracle detector (`tracker.py`) + name-free `classifier.py`. | Opt-in |
| `observability/metrics.py` | All Prometheus counters/gauges/histograms + `record_*` helpers. | Yes |
| `rewrite.py` | Pure `rewrite_wildcard` (enumerate `*` into allowed columns). | Supporting |

`pov/` is a separate validation harness (not shipped in the sidecar): fires a
~230-query tagged corpus through the app and gates on PDR Section 11 criteria
(100% dangerous blocked, 0% false positives, latency, audit completeness).

---

## 4. Key design decisions (and the reasoning)

- **Default-deny, fail-closed core; fail-open guardrail.** Policy + whitelist +
  parser all deny on doubt. Rate limiting is the *only* control that fails open,
  because a Redis outage must not take the SQL protection offline. This split is
  deliberate and load-bearing — see `README.md` "Security Model" and the Charter.

- **The parser is conservative by construction.** Any column it cannot confidently
  attribute to a table becomes `table=None`, which the engine denies (`qualify`)
  when a restricted table is in play. Alias/USING/ORDER-BY handling is scoped
  per-SELECT-block specifically to close alias-shadow bypasses (e.g.
  `SELECT id AS ssn ... WHERE ssn = ...`). Read the long comments in
  `_extract_columns` before touching it — each guards a specific known bypass.

- **Signature privacy is enforced at a single chokepoint.** `signature/facts.py ::
  to_signature_facts` is the *only* code allowed to see real identifiers; it
  converts them to role classes (`restricted`/`allowlisted`/`unlisted`/…) and drops
  the names. Everything downstream is name-free *by type* (no free-text fields).
  A fail-closed `_assert_privacy` guard runs immediately before emit. Signatures
  never contain table names, column names, or literals.

- **Audit integrity via keyed HMAC chain.** Each event signs
  `HMAC(prev_signature ‖ event)`, plus a per-process monotonic `sequence`, plus
  optional signed checkpoints so *tail truncation* is detectable against an
  out-of-band captured head. The SQL is stored only as a **keyed** `sql_digest`
  (HMAC, domain-separated) — a bare `sha256(sql)` is brute-forceable because SQL
  is low-entropy (F8 fix).

- **Fingerprints are policy-relative.** `query_fingerprint` includes role classes
  derived from the *local* policy, so two deployments with different whitelists
  compute different fingerprints for the same query. Cross-deployment immunity
  therefore scopes to deployments that classify an asset the same way. This is the
  honest claim; it is not "universal regardless of config" (see HANDOVER.md).

- **Secrets guard at boot.** The shipped default secrets are ≥32 bytes (so local
  dev works with zero setup), which means a length check alone can't catch them.
  `assert_production_secrets` refuses to boot in `staging`/`production` on the
  known defaults. The base `docker-compose.yml` is fail-closed; only
  `docker-compose.override.yml` (auto-merged locally) flips to `development`.

- **Config as one atomic unit.** Policy, whitelist, and registry reload together or
  not at all (`GovernanceConfigManager`), so a partial/bad config can never open
  the breaker or empty the registry. Hot-reload is opt-in
  (`TERMINUS_CONFIG_RELOAD_INTERVAL`).

- **Telemetry can never change a decision.** Signature matching and velocity run
  *after* the decision and are each wrapped in try/except that degrades to "no
  signal". The intended exception is a *tightening* escalation (allow→deny), which
  is explicit, not a side effect.

---

## 5. Critical paths vs. safe-to-change

**Load-bearing — change with a security mindset, tests, and ideally the
`terminus-reasoner` agent:**
- `parser/sql_parser.py` `_extract_columns` / `_detect_smuggling` / alias handling.
- `policy/policy_engine.py` `evaluate` ordering and the whitelist/column checks.
- `interceptor/router.py` the evaluation order and the fail-safe wrappers.
- `audit/audit_logger.py` `AUDIT_SIGNED_FIELDS` + `_build_event` + `_sign_event`
  (signer and verifier must never drift; a test asserts the field set).
- `config/settings.py` the secret defaults and guards.
- `auth/tokens.py` `verify_token` (alg pinning).

**Safer to change casually** (still test): `remediation/remediation.py` wording,
docs, Grafana dashboard JSON, example YAMLs (but they double as live test
fixtures — see below), the `demo/` pipeline (fully isolated GTM asset, its own
Node tooling, zero product coupling).

**Generated / do-not-hand-edit:** `uv.lock` (regenerated by `uv`), Grafana/
Prometheus provisioning is config not code, `demo/out/**` render artifacts.

---

## 6. Surprising / non-obvious things that will trip you up

1. **It's a decision API with no DB.** (Restated because it's the #1 confusion.)
   All table/column facts are parsed, never introspected.
2. **`examples/*.yaml` are the *live default config* AND test fixtures.** The
   default deployment loads them, and many tests assert against
   `public.users` being column-restricted to `[id, name, email]`. Editing them
   changes real behavior and can turn tests red.
3. **Settings and several engines are cached process singletons.**
   `get_settings()`, `get_governance_manager()` (lru_cache), `get_velocity_trackers()`,
   the signature store, and the audit chain state are all per-process globals.
   Tests must reset caches (see `tests/conftest.py` `reset_*` fixtures) after
   `monkeypatch.setenv`. This also means **multi-worker deployments fragment
   state** — see GAPS.md.
4. **The audit chain resets to genesis every process start.** It is process-scoped
   by design (documented limitation). Durable cross-restart chaining is future work.
5. **`fastapi-limiter` is pinned to 0.1.5** and wrapped by `_SafeRateLimiter`
   because upstream's route-index scan `AttributeError`s on current FastAPI. Do
   not bump it; `0.1.6+` removed the `FastAPILimiter` class this depends on.
6. **`.env` loading is disabled** (`env_file=None`). Only real env vars apply, and
   matching is case-insensitive so `TERMINUS_*` UPPERCASE works. A past bug where
   `case_sensitive=True` silently dropped the audit key is why.
7. **`payload.dialect` is attacker-controlled** and may influence *parse syntax*
   only — never identifier *normalization*, which is pinned to the trusted
   `TERMINUS_SQL_DIALECT`. Mixing these up reopens a whitelist-bypass (F10c).
8. **CI installs `httpx2`** (an unpinned, undeclared package) alongside deps —
   it's what current Starlette's TestClient wants, but it's a rough edge (GAPS.md).
9. **Repo carries a lot of process cruft:** `.claude/worktrees/` (agent worktrees),
   `.superpowers/sdd/*.diff` (review ledger, gitignored), and `docs/superpowers/`
   (per-feature brainstorm→spec→plan artifacts). The specs/plans are genuinely
   useful design history; the diffs are noise.
10. **Signature/velocity/outbound subsystems are large but mostly OFF by default.**
    `signatures_enabled=true` (emit only, local); matching, enforce, outbound,
    velocity, and config-reload are all default-OFF. Reading the code, assume the
    inert path unless a `TERMINUS_*` flag is set.

---

## 7. Where to look for more

- `README.md` — user-facing quick start, API contract, env-var table, metrics.
- `SECURITY.md` — the authoritative security-model writeup (per-control detail).
- `HANDOVER.md` — dense chronological record of every feature sprint (F3–F11, the
  signature flywheel, JWT, GitOps, PoV, demo). Best source for *why a thing exists*.
- `docs/configuration.md`, `docs/operations.md`, `docs/integration.md` — the
  reference docs (kept in-sync-per-commit per the Charter).
- `docs/capabilities/*.md` — one explainer per subsystem.
- `docs/superpowers/specs|plans/*` — design docs per feature, dated.
- `GAPS.md` — honest weakness audit.
- `CLAUDE.md` — operational cheat-sheet for future sessions.

---
---

## Project Charter (preserved — was the prior PROJECT.md)

**Version 1.1 · Authoritative.** These principles and workflow predate this
rewrite and remain binding.

### Mission
Terminus is the **Circuit Breaker for Autonomous Data Operations**: give
enterprises safe, governed, auditable write access for autonomous AI agents to
production databases by intercepting, validating, and (when possible) remediating
database transactions **before** they reach the database engine. We exist because
autonomous agents with production DB access create existential risk and current
guardrails are insufficient at the data plane.

### Core Principles (Non-Negotiable)
1. **Default-Deny** — blocked unless explicitly allowed by policy.
2. **Low Latency First** — sidecar adds < 2 ms p99. Regressions are bugs.
3. **Agent Self-Correction** — denies return structured, actionable remediation.
4. **Compliance-Grade Audit** — every decision logged tamper-evidently, queryable
   for SOC 2 / auditors / incident response.
5. **GitOps & Policy as Code** — policies versioned, reviewable, reproducible.
6. **Fail-Open / Fail-Closed Configurable** — never surprise operators on
   availability decisions.
7. **Dogfood Ruthlessly** — protect our own agents first.
8. **Clarity Over Cleverness** — readable by security/platform engineers.

### Development Workflow
- **Branching:** `main` is protected; never commit directly. Short-lived
  `feature/` , `fix/`, `docs/` branches.
- **Commits:** Conventional Commits (e.g. `security(policy): ...`,
  `fix(remediation): ...`). Commit messages in this repo also carry a security
  finding tag (F3, F8, F10c…) when closing one.
- **PRs:** branch from latest `main`; write code **plus tests plus the matching
  reference doc in the same commit** (a stale doc is worse than none — a
  `TERMINUS_*` var → `docs/configuration.md`; a metric/log/failure-mode →
  `docs/operations.md`; a subsystem change → `docs/capabilities/*`; the
  `/intercept` contract/JWT → `docs/integration.md`; any security change →
  `SECURITY.md`). `make check` clean. One approval. Squash & merge.
- **Testing:** all new functionality has unit tests; run `make check` before every PR.

### Coding Standards
Python 3.11+ · type hints on all public functions · Black + Ruff · async must not
block the event loop · never log full raw SQL by default.

**This charter is the single source of truth for process. Changes require
discussion and a version bump.**
