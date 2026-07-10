# Remediation (Agent Self-Correction)

When Terminus denies a query, it returns machine-readable guidance, and where it
is safe, a ready-to-run corrected query, so the agent fixes itself instead of
failing blind. The consumer-side flow is in
[docs/integration.md](../integration.md); this is how it works on the producer
side.

## What it does

A deny is not a dead end. Every `deny` (and `review`) carries a `remediation`
object in the response body and a compact form in the `X-Terminus-Remediation`
header. The agent reads it, adjusts, and retries. This turns "agent emitted bad
SQL and failed" into "agent self-corrected on the next attempt," which is a major
differentiator over guardrails that only block.

## The remediation object

```json
{
  "message": "why it was blocked and the high-level fix",
  "suggestions": ["concrete step", "another concrete step"],
  "header_value": "the compact form also sent in the X-Terminus-Remediation header",
  "suggested_sql": "SELECT email, id, name FROM public.users"
}
```

- `message` is the policy's `remediation.message` if set, otherwise the decision
  reason.
- `suggestions` are concrete, generated from the parsed metadata.
- `header_value` is the message plus suggestions, flattened and truncated to 500
  characters for the header.
- `suggested_sql` is a **ready-to-run, already-revalidated** safe rewrite, or
  null. It is built only from parsed metadata; raw SQL is never echoed.

## How suggestions are generated

The suggestions are tailored to why the query was denied:

- **Column violation.** Wildcard on a column-restricted table, or a disallowed
  column, names the rejected and the allowed columns. An ambiguous unqualified
  column in a join asks the agent to qualify it as `table.column`.
- **Invalid SQL.** Asks for a single valid statement and suggests passing the
  `dialect` hint.
- **Multiple statements.** Asks for exactly one statement per request.
- **Destructive DDL** (DROP/TRUNCATE/ALTER/CREATE). Suggests an approved
  migration workflow or human approval.
- **DELETE.** Suggests a soft-delete pattern or a policy exception.
- **UPDATE without WHERE.** Suggests adding a selective WHERE clause.
- **High risk score.** Suggests narrowing scope or requesting approval.
- Otherwise, a generic "rewrite to match an explicit allow policy."

## Safe rewrites (`suggested_sql`)

For the specific case of a wildcard on a column-restricted table
(`SELECT * FROM public.users` where only `[id, name, email]` are allowed),
Terminus can hand back a runnable rewrite that enumerates the allowed columns
(`SELECT email, id, name FROM public.users`).

The safety guarantee: the candidate rewrite is **re-validated through the full
engine for the same agent** before it is attached, and it is attached only if it
would now be allowed. Terminus never hands back SQL that still violates policy. If
any wildcard cannot be safely enumerated (for example a derived table in the
`FROM`), no rewrite is offered. The rewrite appears in the JSON body only, never
in the header, and the audit log records a `rewrite_suggested` boolean, not the
SQL.

## How to use

This requires no configuration; remediation is always built for deny/review
decisions. On the agent side: on a 403, prefer `suggested_sql` when present
(retry with it directly), otherwise feed `message` + `suggestions` back into the
agent to produce a corrected query, and cap retries so a genuine policy boundary
is surfaced rather than looped on. See [docs/integration.md](../integration.md)
for a worked client.
