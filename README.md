# Terminus

**The SQL firewall for AI agents.** A default-deny sidecar that decides what every
query an AI agent runs against your database is allowed to do, before it runs.

By [InterceptAI](https://interceptai.tech) · [@intercept_ai](https://x.com/intercept_ai)

> Prompt guardrails watch what your agent *says*. Almost nothing watches what it
> *runs* against your database. That gap is Terminus.

License: AGPL-3.0 (commercial license available) · Status: pre-1.0, single-DB today

---

## The problem

Teams are giving AI agents access to production databases. The usual defenses are the
wrong shape:

- **Prompt guardrails** (Lakera, LLM Guard) govern what the model *says*. They do not
  stop a valid, destructive `DELETE` the agent decides to run.
- **Data-access proxies** (Satori, Cyral) and **DB firewalls** (Imperva, DataSunrise)
  govern SQL, but they were built for humans and BI tools hitting warehouses, not for
  agents hitting your operational database.
- **The hand-rolled blocklist** (a read replica, a restricted user, a list of banned
  keywords) is what most teams actually do. A keyword blocklist sails right past a
  comment-obfuscated subquery, a read replica does not stop read-scope exfiltration or
  enforce per-agent column policy, and you maintain it forever.

Nobody was governing what an *agent does to the database*. That is the layer Terminus
owns.

## What Terminus does (shipped)

Terminus parses the SQL with `sqlglot` and returns allow, deny, or a safe rewrite. It
has **no database of its own**, every decision comes from the SQL string, never a live
schema, so it is fast and stateless per query.

- **Default-deny at the action layer.** A policy engine enforces a schema and column
  whitelist, blocks multi-statement and injection-function abuse, catches writes nested
  in reads (writable CTEs), and denies anything not explicitly allowed.
- **Per-agent identity.** Every request is gated by a per-agent JWT, so each agent can
  only run what you allowed *it* to run.
- **It fixes, not just blocks.** A denied query comes back with a policy-compliant
  rewrite, re-validated through the same engine, so the agent retries and keeps working.
- **The MCP enforcement point (unbypassable by construction).** Run Terminus as the MCP
  server your agent calls, exposing only `query` and `execute`. The agent never holds a
  database connection string; the executor alone holds credentials and runs nothing the
  policy engine did not already allow. High-risk writes wait for a human.
- **Provable, not just logged.** Every decision lands in a tamper-evident, independently
  verifiable HMAC audit chain. Raw SQL is never stored, only a keyed digest. This is the
  evidence an EU AI Act, SOC 2, or DORA auditor asks for, not logs you have to trust.
- **Composes with your prompt guardrails.** They guard the conversation; Terminus guards
  the database action. Run both.

## Quickstart

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/). Run from the repo root.

```bash
# install
uv pip install --system -e ".[dev]"

# run the decision sidecar (Redis optional; the limiter fails open without it)
PYTHONPATH=src uv run uvicorn terminus.main:app --reload --port 8000
curl http://localhost:8000/health

# ask it about a query
curl -s localhost:8000/intercept -H 'Content-Type: application/json' \
  -d '{"sql":"SELECT id, email FROM public.users WHERE id = 42","agent_id":"analytics_agent_42"}' | jq
```

To run the **MCP enforcement point** (structural no-bypass, holds the DB credentials):

```bash
TERMINUS_MCP_ENABLED=true python -m terminus.mcp
```

Policy, schema whitelist, and agent identities are plain YAML you version-control. See
`examples/` and the docs below.

## How it works

Everything is default-deny and fail-closed: a query executes only on an explicit allow,
and anything Terminus is unsure about is denied. The MCP enforcement point makes this
structural, the only path to the data is the two typed tools, and the executor accepts
only a grant that a policy allow minted. See `docs/capabilities/` for the parser,
policy engine, MCP enforcement point, audit chain, and remediation in depth, and
`SECURITY.md` for the security model.

## Open core

The enforcement core in this repo is free and open under **AGPL-3.0**: the sidecar, the
MCP enforcement point, the policy engine, per-agent identity, remediation, and the local
verifiable audit chain. Self-host it, read every line, put it in your critical path
without depending on anyone's uptime.

The **Terminus control plane** is the commercial layer, for teams that want to operate
this across a fleet:

- **Least-privilege autopilot** *(roadmap)*: Terminus observes what each agent actually
  accesses and proposes a tightened least-privilege policy, so you do not hand-write and
  maintain it. Drift detection when an agent reaches somewhere new.
- **Central approvals** *(roadmap)*: one operator pane to approve or deny high-risk writes
  held across every agent server, signed into the audit chain.
- **Audit witness and index** *(roadmap)*: the external, tamper-evident witness and
  one-pane place to verify and locate events, and to route your logs to your own SIEM.

A commercial license is also available for teams that cannot use AGPL. Contact
[will@interceptai.tech](mailto:will@interceptai.tech).

## Honest limits

- **Single database per deployment today.** Multi-DB is on the roadmap.
- **Terminus does not read prompts or model output.** It governs the database action,
  not what the agent thinks or says. Pair it with a prompt guardrail.
- **It does not guess intent inside a valid query on an allowed table.** It bounds what
  the agent can do so intent inside those bounds does not have to be guessed. That is a
  WAF's losing game, not ours.
- **The autopilot and control plane above are roadmap, not shipped.** What is shipped is
  the enforcement core and the verifiable audit chain.

## Security

Found a way past the enforcement? Please disclose it responsibly:
[security@interceptai.tech](mailto:security@interceptai.tech). Do not open a public issue
for a vulnerability. See `SECURITY.md` for the security model and the disclosure process.

## Contributing

Terminus is built in the open because a security control you cannot read is a security
control you cannot trust. Issues, threat models, policy examples, and new database
dialects are all welcome. See `CONTRIBUTING.md`.

## License

AGPL-3.0 for the open-source core (see `LICENSE`). A commercial license is available for
teams that cannot comply with AGPL, and for the Terminus control plane. Contributions are
accepted under the project's contributor terms (see `CONTRIBUTING.md`).
