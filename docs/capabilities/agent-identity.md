# Agent Identity (JWT)

Cryptographically verifiable per-agent identity, so per-agent policy and rate
limits cannot be spoofed by a forged header. Configuration is in
[docs/configuration.md](../configuration.md); the security model is in
SECURITY.md.

## What it does

Without authentication, an agent's identity is whatever it claims in the
`agent_id` body field or `X-Agent-ID` header, trivially spoofable. With JWT
identity, an agent presents a signed token and Terminus derives the **trusted**
agent id from the verified `sub` claim. That trusted id then drives policy, rate
limiting, and logging; the self-asserted values are ignored.

## How it works

- **Algorithm:** HS256, pinned. The verifier rejects `alg=none` and algorithm
  confusion. A shared secret (`TERMINUS_JWT_SECRET`) signs and verifies.
- **Registry-gated:** the verified `sub` must be a registered, active agent in
  `TERMINUS_AGENT_REGISTRY_PATH`. An unknown or disabled `sub` is rejected even
  with a valid signature, this is how you revoke an agent without rotating the
  secret.
- **Tokens are minted out of band**, never at runtime, by an operator CLI.
- **Fail closed:** a missing or unparseable registry yields an empty registry, so
  every authenticated request is rejected, and the problem is logged
  (`agent_registry_missing` / `agent_registry_unparseable`).

`agents.yaml`:

```yaml
version: "1.0"
agents:
  - id: analytics_agent_42
    description: "Production analytics reader"
  - id: reporting_cron
    description: "Nightly reporting job"
  - id: experimental_agent_7
    description: "Sandbox agent, currently deregistered"
    status: disabled        # disabled (or removed) = revoked
```

Unknown extra fields on an entry (e.g. `policy_profile`, `rate_limit_tier`,
`owner`) are reserved forward-compat metadata: accepted and ignored by
design, no behavior today; live behavior depends on `id`, `status`,
and `trust_level` (graduated autonomy; see
[docs/capabilities/graduated-autonomy.md](graduated-autonomy.md)).

## Issuing tokens

```bash
python -m terminus.auth issue --agent analytics_agent_42            # 30-day token
python -m terminus.auth issue --agent analytics_agent_42 --expires-days 7
python -m terminus.auth issue --agent reporting_cron --no-expiry    # development/compat only
```

The `--agent` value must be a registered, active agent. The command prints the
token; the agent sends it as `Authorization: Bearer <jwt>` on every request.

`--no-expiry` mints a token with no `exp` claim. It verifies only on the
non-hardened path (`TERMINUS_JWT_REQUIRE_EXP=false`), so treat it as a
development or legacy-compatibility escape, never something to mint for
staging or production.

## Enforcement rules

When a **valid** JWT is present, its `sub` is the trusted agent id and overrides
`agent_id` / `X-Agent-ID` for identity, policy, rate limiting, and logging. This
rule is absolute. Otherwise:

| Scenario | `TERMINUS_REQUIRE_AUTH=false` (default) | `=true` |
|----------|------------------------------------------|---------|
| Valid token, `sub` registered + active | use `sub` | use `sub` |
| No `Authorization` header | self-asserted path (logs `auth_legacy_unauthenticated`) | 401 |
| Invalid / expired / wrong-alg token | **401** | 401 |
| Unknown / disabled `sub` | **401** | 401 |

The key invariants: an invalid token is **always** 401 (even in permissive mode,
no fallback to self-asserted on a bad token); `REQUIRE_AUTH` governs only the
completely-absent-token case, for safe migration. A 401 carries
`WWW-Authenticate: Bearer` and parses no SQL.

## Expiry and lifetime enforcement

Two independent, additive checks, both hardened by default and both folding
into the same flat `invalid_token` reason (no signal to an attacker about which
check failed):

- **`TERMINUS_JWT_REQUIRE_EXP`** (bool; auto `false` in development, `true` in
  staging/production). When `true`, a token with no `exp` claim is rejected. A
  present `exp` is always checked with zero clock leeway, regardless of this
  setting; this flag only controls whether `exp` must be present at all.
- **`TERMINUS_JWT_MAX_LIFETIME_SECONDS`** (int seconds; default `0`, no cap).
  When `> 0`, the *minted* lifetime (`exp - iat`) must not exceed the cap, and
  both `exp` and `iat` become mandatory integer claims regardless of
  `TERMINUS_JWT_REQUIRE_EXP`. This catches a token that has an expiry but was
  minted with an excessive one (a one-year token is still rejected under a
  one-day cap).

`--no-expiry` is a development/compatibility escape only: it mints a token
with no `exp` claim, so it verifies only where `TERMINUS_JWT_REQUIRE_EXP=false`.
See [docs/configuration.md](../configuration.md) for the full field reference
and [SECURITY.md](../../SECURITY.md) for the rollout hazard when enabling this
on an environment with pre-existing non-expiring tokens.

## How to use

1. Generate a strong `TERMINUS_JWT_SECRET` (>= 32 bytes, via your secret manager)
   and point `TERMINUS_AGENT_REGISTRY_PATH` at your registry.
2. Issue tokens to each agent and have them send the Bearer header.
3. Watch `terminus_auth_events_total`: `verified` should dominate; nonzero
   `legacy` means agents are still on the self-asserted path.
4. Once every agent presents a JWT, set `TERMINUS_REQUIRE_AUTH=true` to remove the
   fallback.
5. Revoke an agent by setting `status: disabled` (or removing it) in the
   registry, no secret rotation required.
