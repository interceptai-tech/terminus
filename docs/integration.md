# Integrating an Agent with Terminus

For developers wiring an AI agent (or any SQL-emitting service) to call Terminus
before it touches a database. Covers the `/intercept` contract, agent identity,
the self-correction loop, and a worked client. Configuration is in
[docs/configuration.md](configuration.md); the security model is in SECURITY.md.

## Where Terminus sits

Terminus is a sidecar between your agent and your database. Instead of executing
SQL directly, your agent (or your data-access layer) sends each statement to
`POST /intercept` first. Terminus returns allow or deny; you execute only on
allow, and on deny you get machine-readable guidance to fix and retry.

```
agent --(SQL)--> POST /intercept --> allow (200) --> you run the SQL against the DB
                                  \-> deny  (403) --> you read remediation, fix, retry
```

## The `/intercept` contract

**Request** (`POST /intercept`, `Content-Type: application/json`):

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `sql` | string | yes | exactly one SQL statement (1 to 1,000,000 chars) |
| `agent_id` | string | no | self-asserted identity; **ignored when a JWT is present** (see Identity) |
| `dialect` | string | no | sqlglot dialect hint, e.g. `postgres`; affects PARSE syntax only (quote characters, grammar) when `TERMINUS_SQL_DIALECT` is unset. It never affects identifier normalization or schema-whitelist/policy matching, which always use the trusted, operator-configured `TERMINUS_SQL_DIALECT` (empty = generic/lowercase) -- this field is client-supplied and untrusted, so it cannot be used to influence what gets matched |
| `request_id` | string | no | correlation id; auto-generated (uuid4) if omitted |
| `metadata` | object | no | arbitrary key/value context; at most 64 top-level keys, one nesting level (containers at depth 3 rejected with a 422); only the key names are recorded |

**Response** (`200` allow, `403` deny or review):

| Field | Type | Notes |
|-------|------|-------|
| `decision` | string | `allow`, `deny`, or `review` |
| `request_id` | string | echoes your correlation id |
| `operation` | string | parsed operation (SELECT, UPDATE, ...) |
| `tables` | string[] | referenced tables |
| `risk_score` | number | 0.0 to 1.0 |
| `policy_id` | string \| null | the rule (or gate) that decided |
| `reason` | string | human-readable explanation |
| `risk_reasons` | string[] | low-cardinality risk tags |
| `remediation` | object \| null | present on deny/review (see below) |

A deny also carries the compact guidance in an `X-Terminus-Remediation` response
header (handy if you only read headers). **Raw SQL is never echoed** in any
response, header, or log, only a SHA-256 digest is recorded server-side.

The `remediation` object:

| Field | Type | Notes |
|-------|------|-------|
| `message` | string | why it was blocked and the high-level fix |
| `suggestions` | string[] | concrete steps (e.g. allowed columns, add a WHERE) |
| `header_value` | string | the compact form also sent in the header |
| `suggested_sql` | string \| null | a **ready-to-run, already-revalidated** safe rewrite, when one exists |

### Graduated autonomy changes what `decision=allow` can mean

If `TERMINUS_GRADUATED_AUTONOMY_ENABLED=true` and your agent is registered
with `trust_level: observe` in `agents.yaml`, a `200` allow response no longer
always means "policy allowed this query outright." It can also mean "policy
would have denied this, but the agent is in observe mode and the deny was
softened to evidence instead." Full detail (the exact softenable/floor
reason-code lists, the identity rule, the promotion runbook) is in
[docs/capabilities/graduated-autonomy.md](capabilities/graduated-autonomy.md);
this section covers only what changes in the `/intercept` response you parse.

- **The HTTP contract does not grow a new field.** A softened decision is
  still `decision: "allow"` with `200`, same shape as any other allow. What
  changes is `risk_reasons`: a softened response carries an additional
  `"would_deny:<original_reason_code>"` entry, e.g.
  `"would_deny:schema_whitelist"` or `"would_deny:policy_rule"`, alongside
  whatever risk tags were already present. This is the ONLY signal in the
  synchronous response that the query would have been denied under enforce;
  everything else (the human-readable "why", the original decision) is
  recorded in the audit chain, not returned to the caller.
- **The full evidence lives in audit, not in the response.** Every softened
  decision is also written to the tamper-evident audit chain with
  `decision=allow`, `reason_code=observe_softened`, `would_deny=true`, and
  `would_deny_reason_code=<original code>` (audit schema v3; see
  [docs/capabilities/audit.md](capabilities/audit.md)). If you are building
  tooling that needs to know WHY a query was softened (not just that it was),
  read the audit stream rather than trying to infer it from `/intercept`'s
  response body.
- **Do not treat `would_deny:*` in `risk_reasons` as advisory noise to
  ignore.** It is the operator's promotion-evidence signal
  (`terminus_would_deny_total` in Prometheus is the aggregate view); if your
  integration surfaces `risk_reasons` to a dashboard or a human reviewer,
  keep this one visible.
- **Recommend `TERMINUS_REQUIRE_AUTH=true` once graduated autonomy is on.**
  Observe-mode softening is honored only for a JWT-verified agent identity;
  a self-asserted `agent_id` on the legacy unauthenticated path is always
  treated as enforce, regardless of what the registry says for that id (the
  F9-style anti-spoofing rule; see
  [docs/capabilities/graduated-autonomy.md](capabilities/graduated-autonomy.md#the-identity-rule-f9-lesson-inverted)).
  That is correct and safe on its own, but it also means an agent you
  intended to onboard in observe mode gets no benefit from that setting
  until it authenticates. If you are relying on graduated autonomy at all,
  finish the JWT rollout (see Identity below) and set
  `TERMINUS_REQUIRE_AUTH=true` so every agent that matters is actually
  eligible for the softer posture you configured for it.

## Identity (agent authentication)

By default (`TERMINUS_REQUIRE_AUTH=false`), an agent's identity is whatever it
puts in `agent_id`, which is spoofable. For real per-agent policy and rate
limits, agents authenticate with a signed JWT.

**Issue a token** (operator, out of band):

```bash
python -m terminus.auth issue --agent analytics_agent_42            # 30-day token
python -m terminus.auth issue --agent analytics_agent_42 --expires-days 7
python -m terminus.auth issue --agent reporting_cron --no-expiry    # development/compat only
```

The `--agent` value must be registered and active in the agent registry
(`TERMINUS_AGENT_REGISTRY_PATH`). The command prints the token.

**Send it** on every request:

```
Authorization: Bearer <jwt>
```

When a valid JWT is present, its `sub` claim is the **trusted** agent id and
overrides any `agent_id` in the body or `X-Agent-ID` header for identity, policy,
rate limiting, and logging. An invalid, expired, or unknown-`sub` token always
gets `401` (even when `REQUIRE_AUTH=false`); only the completely-absent-token case
falls back to the self-asserted path. Set `TERMINUS_REQUIRE_AUTH=true` once all
your agents present JWTs to remove that fallback. Revoke an agent by disabling or
removing it from the registry, no secret rotation needed.

**Expiry is enforced, hardened by default.** `TERMINUS_JWT_REQUIRE_EXP` defaults
to `false` in development and `true` in staging/production; when `true`, a token
without an `exp` claim is rejected (`401`, `invalid_token`). `--no-expiry` mints a
token with no `exp` claim at all, so it verifies only where `require_exp=false`:
treat it as a development/compatibility escape, not something to run in staging
or production. `TERMINUS_JWT_MAX_LIFETIME_SECONDS` (default `0`, no cap) separately
caps the *minted* lifetime (`exp - iat`); when set `> 0`, both `exp` and `iat`
become mandatory claims regardless of `require_exp`, so a token minted with a
multi-year expiry is rejected even though it technically has one. Both checks
fold into the same flat `invalid_token` reason (no probing signal for which
check failed); an unknown or disabled `sub` still reports `unknown_agent`
separately. See [docs/capabilities/agent-identity.md](capabilities/agent-identity.md)
for the full enforcement table.

## The self-correction loop

The point of the deny path is that your agent can fix itself rather than fail. On
a `403`:

1. Read `remediation`.
2. If `suggested_sql` is non-null, it is a safe rewrite Terminus already
   re-validated for your agent (for example, a `SELECT *` on a column-restricted
   table rewritten to the allowed columns). Retry with it.
3. Otherwise, feed `message` + `suggestions` back to the agent (or your logic) to
   produce a corrected query, and retry.

Do not loop forever: cap retries, and treat a persistent deny as a real policy
boundary (some operations require human approval by design).

## Worked client (Python)

```python
import httpx

TERMINUS = "http://localhost:8000"


def run_guarded(sql: str, token: str, *, dialect: str = "postgres") -> dict:
    """Send one statement through Terminus. Returns the decision dict.

    On an enforce deny with a re-validated suggested_sql, retries once with it.
    """
    headers = {"Authorization": f"Bearer {token}"}

    def intercept(statement: str) -> httpx.Response:
        return httpx.post(
            f"{TERMINUS}/intercept",
            headers=headers,
            json={"sql": statement, "dialect": dialect},
            timeout=5.0,
        )

    resp = intercept(sql)
    if resp.status_code == 200:
        return resp.json()  # allow: safe to execute `sql` against the DB

    body = resp.json()  # 403: a deny (or review)
    suggested = (body.get("remediation") or {}).get("suggested_sql")
    if suggested:
        retry = intercept(suggested)
        if retry.status_code == 200:
            return retry.json()  # the rewrite is allowed; execute `suggested`
    return body  # still denied: surface reason + remediation to your agent/operator
```

Then, in your data layer, execute the statement **only** when `decision ==
"allow"`, using the exact SQL that was allowed (the original, or `suggested_sql`
if you retried with it).

## Alternative: the MCP enforcement point

Everything above integrates an agent that still holds its own database
credentials and calls `/intercept` voluntarily before running SQL. If you want
the agent to never hold credentials at all, so obeying Terminus is not a
choice the agent's code makes, run the MCP enforcement point instead:

```bash
python -m terminus.mcp
```

Configure it with `TERMINUS_MCP_ENABLED=true`, `TERMINUS_MCP_AGENT_ID=<id>`
(must be registered and active in `TERMINUS_AGENT_REGISTRY_PATH`, same
registry as JWT identity above), and `TERMINUS_MCP_POSTGRES_DSN=<dsn>`. Point
your agent's MCP client at this server instead of a database connection;
it exposes exactly two tools, `query` (read-only `SELECT`) and `execute`
(writes), each gated by the same parser and policy engine as `/intercept`.
High-risk writes (by default, risk score >= `TERMINUS_MCP_APPROVAL_RISK_THRESHOLD`,
`0.8`) are held for human approval rather than run immediately. See
[docs/capabilities/mcp-enforcement-point.md](capabilities/mcp-enforcement-point.md)
for the full model, including the deployment topology (network segmentation)
that makes it unbypassable, the approval flow, and the audit binding. All
settings are documented in [docs/configuration.md](configuration.md).

### See it live

`dogfood/README.md` is a reference MCP-client integration: a real LangGraph
agent, backed by a real model, making real writes through this MCP
enforcement point against a throwaway Postgres database, with an allowed
write, a blocked destructive write, a self-corrected wildcard query, and a
verified audit chain, all checked against actual database state and the
signed audit log rather than the agent's own account of what happened. Run
it with `make dogfood` (needs Docker and `ANTHROPIC_API_KEY`, about
$0.13/run) or `make dogfood-smoke` (wiring check, no model calls).

### Running the enforcement point in a container

The MCP enforcement point has no special container requirements: it is a
process that speaks MCP over stdio, so any host that can run `docker run -i`
and attach the container's stdin/stdout can use it. The client-config server
command is:

```bash
docker run -i --rm \
  -e TERMINUS_MCP_ENABLED=true \
  -e TERMINUS_MCP_AGENT_ID=<id> \
  -e TERMINUS_MCP_POSTGRES_DSN=<dsn> \
  <image> python -m terminus.mcp
```

Points to know before wiring this into an agent host:

- **`-i` is required.** The stdio transport needs stdin attached; without it
  the MCP client's handshake never completes.
- **stdout is a protocol channel, not a log stream.** It carries MCP protocol
  frames and must not be polluted with anything else. Terminus already logs
  to stderr when run this way (`python -m terminus.mcp` configures this on
  startup), so application logs never collide with the wire format.
- **One container per agent identity.** `TERMINUS_MCP_AGENT_ID` is fixed at
  container start, so the reference deployment model is one container per
  agent identity, not one shared container multiplexing several agents. This
  keeps the credential-holding boundary aligned with the agent boundary.
- **Networking is asymmetric.** The container needs a route to Postgres (in
  the smoke test below, via `host.docker.internal`, since the database runs
  on the Docker host); the agent host, in turn, only needs the container's
  stdio, never a direct database connection or credential.
- **Secrets go in via environment or a secrets manager, never the image.**
  `TERMINUS_MCP_POSTGRES_DSN` and any JWT/HMAC keys should be injected at
  `docker run` time (or via your orchestrator's secret-mounting mechanism);
  they must never be baked into the image itself.

`make mcp-docker-smoke` is the deploy-cycle check for this: it builds the
image, brings up the dogfood Postgres, spawns the containerized server over
stdio, performs the MCP initialize handshake and a `tools/list`, and asserts
exactly `query` and `execute` are exposed. CI wiring for it is intentionally
not included, since it needs a live Postgres; that coverage boundary is
explicit rather than silently missing.

## Gotchas

- **One statement per request.** Multiple statements are denied
  (`reason_code=multi_statement`). Send them individually.
- **A write nested in a CTE is denied.** A statement is classified by its
  top-level operation only, so `WITH d AS (DELETE FROM t RETURNING id) SELECT 1`
  is classified as SELECT, but Terminus still denies it
  (`reason_code=nested_write`) because the CTE body contains a data-modifying
  operation (INSERT, UPDATE, DELETE, MERGE). Submit the write as its own
  top-level statement so policy can evaluate it.
- **A `429` is the rate limit**, not a policy decision: you exceeded
  `TERMINUS_RATE_LIMIT_PER_MINUTE` for your agent. Back off and retry.
- **Pass `dialect`** when you know it; it makes parsing (and therefore the
  decision) more accurate.
- **`X-Agent-ID` is ignored when a JWT is present.** Use the JWT for identity in
  any environment where the identity matters.
- **Metadata is for context, not secrets.** Only the metadata key names are
  recorded, but do not put sensitive values there as a matter of habit. It is
  also shape-bounded: at most 64 top-level keys and one nesting level, or the
  request is rejected with a 422.
- **Oversized or malformed SQL fails closed.** SQL longer than
  `TERMINUS_MAX_SQL_LENGTH` (default 16 KiB) returns `403` deny
  (`reason_code=oversize_sql`); an unknown `dialect` or unparseable/pathological
  SQL returns `403` deny (`reason_code=invalid_sql`). A `sql` field over 128 KiB
  is a `422`; a whole request body over `TERMINUS_MAX_REQUEST_BODY_BYTES` (default
  256 KiB) is rejected with `413` before it reaches policy.
