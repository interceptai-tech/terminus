# Policy and Whitelists

The default-deny core of Terminus: which tables and columns an agent may touch,
and what it may do to them. Configuration variables are in
[docs/configuration.md](../configuration.md); the deny reason codes appear in
[docs/operations.md](../operations.md).

## What it does

Five gates decide every query, in this order. The first to deny wins, and the
default is always deny.

1. **Schema whitelist** (`TERMINUS_SCHEMA_WHITELIST_PATH`): a default-deny
   allow-list of the only tables an agent may reference at all.
2. **Column whitelist** (same file): for a whitelisted table that opts in, the
   only columns that may be selected.
3. **Injection-function gate** (`TERMINUS_ENFORCE_INJECTION_BLOCK`, default on):
   denies a query that calls an injection or time-based SQL function on the
   allow path (see below).
4. **Nested-write gate** (no config toggle): denies a statement whose CTE body
   hides a data-modifying operation (INSERT, UPDATE, DELETE, MERGE) that the
   top-level operation classification would otherwise miss (see below).
5. **Policy rules** (`TERMINUS_POLICY_PATH`): priority-ordered rules deciding
   what operation may be performed on an approved table, by which agent, under
   what conditions.

Think of the whitelist as a firewall allow-list at the data layer (which tables
are reachable) and the policy as the access rules (what may be done to them).

## Schema and column whitelist

`schema_whitelist.yaml`:

```yaml
version: "1.0"
enabled: true            # set false to disable whitelist enforcement (policy still runs)
tables:
  - public.users:        # object form opts this table into a column allow-list
      columns: [id, name, email]
  - public.orders        # string form: all columns allowed
  - analytics.*          # shell-style glob: every table in the analytics schema
remediation_message: "..."
```

Behavior:

- Tables are matched **case-insensitively** in normalized `schema.table` form,
  with shell-style globs (`analytics.*`).
- Table identifier matching is quote-aware too, mirroring the column behavior
  below: an unquoted table name, including its schema/catalog qualifiers and
  aliases, is case-insensitive and folded to lowercase before matching, while a
  quoted table name is case-sensitive and matched exactly against the
  (lowercased) whitelist patterns, so a quoted case-variant of a whitelisted
  table, e.g. `SELECT id FROM "public"."USERS"` where the whitelist has
  `public.users`, is denied (`reason_code=schema_whitelist`) rather than
  allowed. As with columns, this is fail-closed: a genuinely quoted mixed-case
  table cannot be whitelisted, since config patterns are still case-folded.
- A query that references any non-matched table is denied immediately with
  `reason_code=schema_whitelist`, regardless of operation or policy.
- For a column-restricted table, selecting a non-allowed column, a wildcard
  (`*` or `t.*`), or an unqualified column in a join where the table is
  ambiguous, is denied with `reason_code=column_whitelist`. Column attribution is
  conservative and fail-closed: anything it cannot confidently attribute is
  denied rather than allowed.
- Column identifier matching is quote-aware: an unquoted column name is
  case-insensitive (folded to lowercase before matching), while a quoted column
  name is case-sensitive and matched exactly against the (lowercased)
  allowlist, so a quoted case-variant of an allowlisted column is denied rather
  than allowed. This applies everywhere a column is checked, including an
  `ORDER BY` term that only appears to reference a select-list alias. The same
  applies to table identifiers (above). Matching now follows the deployment's
  configured `TERMINUS_SQL_DIALECT` (default empty, meaning generic/Postgres
  `LOWERCASE`): both query identifiers and the whitelist/policy config are
  folded per that dialect, so a quoted or unquoted identifier under Snowflake
  (which unquoted-folds to UPPERCASE) or another non-lowercase dialect is
  matched correctly instead of being blind to the dialect's case rules. A
  genuinely quoted mixed-case object still cannot be expressed in the
  whitelist, since config identifiers are folded as unquoted; that is a
  fail-closed over-deny, not a bypass.
- INSERT target column lists are checked identically to UPDATE SET: a
  non-allowlisted column named in the INSERT column list is denied with
  `reason_code=column_whitelist`. An INSERT with no column list on a
  column-restricted table (a bare `INSERT INTO t VALUES (...)` or
  `DEFAULT VALUES`) writes every column implicitly and is denied outright,
  the same reasoning as a bare wildcard.
- Globs are always all-columns; a glob entry with a `columns:` list is warned
  about and the column list ignored (one list cannot sensibly span many tables).

## Injection and time-based function gate

A fourth gate runs after the whitelist and column checks and before the policy
rules: it inspects the `sqlglot` AST for calls to injection or time-based SQL
functions (`pg_sleep`, `sleep`, `benchmark`, `waitfor`, `xp_cmdshell`,
`pg_read_file`, ...) and denies them on the allow path with
`reason_code=injection_function`, even if a policy rule would otherwise allow
the query. It is governed by `TERMINUS_ENFORCE_INJECTION_BLOCK` (default
`true`; set `false` to make it observe-only). Detection is AST-based, not
substring matching, so a type name like `varchar(255)` is never confused with
the `char()` function.

## Nested-write gate (writable CTEs)

A fifth gate runs after the whitelist, column, and injection-function checks,
and before the policy rules: it inspects every CTE body in the `sqlglot` AST
for a data-modifying operation (INSERT, UPDATE, DELETE, MERGE) and denies the
statement outright with `reason_code=nested_write`, even if the top-level
operation would otherwise be allowed. This closes a gap where a statement is
classified by its top-level operation only, so a query like `WITH d AS (DELETE
FROM t RETURNING id) SELECT 1` is classified as SELECT and the
destructive-operation policy rules would otherwise never see the nested DELETE.
Detection is by CTE body, so a normal top-level MERGE, whose WHEN arms are
internally INSERT/UPDATE, is not affected. Unlike the injection-function gate,
this is not governed by an environment variable: under a default-deny posture, a
write smuggled inside a CTE has no benign reading. This denies
legitimately-intended writable CTEs too, for example `WITH moved AS (DELETE FROM
orders ... RETURNING *) INSERT INTO archive SELECT * FROM moved`; submit the
write as its own top-level statement so policy can evaluate it.

## Policy rules

`policy.yaml`:

```yaml
version: "1.0"
default_action: deny
default_remediation_message: "..."
policies:
  - id: "allow_analytics_reads"
    name: "Allow read-only analytics queries on approved tables"
    priority: 10
    match:
      operation: ["SELECT"]
      tables: ["public.users", "public.orders", "analytics.*"]
      agent_ids: ["analytics_agent_*", "reporting_cron"]
    action: allow
  - id: "block_all_destructive_operations"
    name: "Block destructive schema and data operations"
    priority: 100
    match:
      operation: ["DROP", "TRUNCATE", "ALTER", "CREATE", "DELETE"]
    action: deny
    remediation:
      message: "Destructive operations require explicit human approval."
      auto_suggest: true
```

Rule evaluation:

- Rules are evaluated in **descending priority**. The first rule whose `match`
  matches decides; if none match, `default_action` (deny) applies
  (`reason_code=default`).
- `match` fields are all optional and ANDed: `operation` (list), `tables` (list,
  glob-aware, matches if any referenced table matches), `agent_ids` (list,
  glob-aware, matched against the trusted or self-asserted agent id), and
  `conditions.has_where` (true/false).
- A matched rule's `action` is `allow`, `deny`, or `review`. A deny uses
  `reason_code=policy_rule`.

### Rule limits

A rule may carry `limits`:

```yaml
    limits:
      max_queries_per_minute: 60          # parsed, NOT enforced in v0.1 (see below)
      max_destructive_risk_score: 0.2
```

- `max_destructive_risk_score` **is enforced**: if the parsed query's risk score
  exceeds it, the query is denied with `reason_code=risk_threshold`.
- `max_queries_per_minute` is parsed for forward compatibility but **not**
  enforced here. The actual per-agent rate limit is the Redis-backed
  `TERMINUS_RATE_LIMIT_PER_MINUTE` on `/intercept` (a `429`, separate from policy
  decisions).

## How to use

- Point `TERMINUS_POLICY_PATH` and `TERMINUS_SCHEMA_WHITELIST_PATH` at your own
  files (the bundled `examples/` are demos). Both live as code in Git: reviewable
  and auditable.
- Start strict (small whitelist, minimal allow rules) and widen deliberately. The
  default-deny posture means a missing rule fails safe.
- The decision and the gate that made it are recorded on every audit event and on
  `terminus_requests_total{reason}`; a rising deny rate by reason tells you which
  gate is blocking traffic.

## Hot-reload (GitOps)

By default, `TERMINUS_CONFIG_RELOAD_INTERVAL=0` and the three governance files
(policy, whitelist, registry) are loaded once at startup. Set the interval to a
positive integer (seconds) to enable GitOps hot-reload without a sidecar restart:

```
TERMINUS_CONFIG_RELOAD_INTERVAL=30
```

How it works:

- **Atomic, all-or-nothing reload.** The sidecar polls all three configured
  paths, validates them together as a single unit, and atomically swaps the active
  snapshot on a successful change. There is no window where one file is new and
  another is old.
- **Last-known-good on failure.** If any file fails validation, the entire
  reload is discarded and the prior snapshot stays in force. A malformed push
  never opens the circuit breaker or empties the agent registry.
- **Live agent revocation.** Disable an agent in `agents.yaml` (set
  `status: disabled`), push the file to the configured path, and the next request
  from that agent is rejected. No restart required.
- **Change detection.** The sidecar computes a combined SHA-256 hash over the
  raw bytes of all three files (in fixed order). A poll that sees no change
  records `unchanged` and returns immediately, so disk I/O is minimal.

### GitOps delivery patterns

Standard tooling works as-is: the sidecar reads from local file paths, so
anything that writes those paths is sufficient.

- **git-sync sidecar:** mount a shared volume; git-sync writes the files, Terminus
  polls and reloads.
- **Kubernetes ConfigMap:** mount the ConfigMap as a volume; Kubernetes rotates the
  symlink atomically when the ConfigMap is updated.
- **Argo CD / Flux:** deploy updated files to the path via your GitOps controller;
  the sidecar picks up the change on the next poll cycle.

### Metrics and observability

Each poll cycle records a `terminus_config_reloads_total{result}` counter with
result `applied`, `unchanged`, or `failed`, and updates
`terminus_config_last_reload_timestamp` (epoch seconds) on a successful apply.
Alert on `terminus_config_reloads_total{result="failed"}` to catch bad pushes.
