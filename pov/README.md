# Terminus PoV Validation Harness

Automated proof-of-value harness for Terminus. Runs the PDR Section 11 criteria
in-process and (optionally) against a deployed server, then exits non-zero if any
hard criterion fails.

## What It Validates

The harness measures five criteria defined in PDR Section 11:

| Criterion | Threshold |
|-----------|-----------|
| Safety: all dangerous queries blocked | 100% |
| Self-correction rate | > 60% |
| Audit completeness + chain integrity | 100% (every request audited, chain verified) |
| Decision compute latency p99 | < 2 ms |
| False-positive rate on benign queries | < 5% |

The headline latency number is the **in-process decision compute**: parse + policy
evaluate, with no HTTP, ASGI, or network overhead. This is the latency Terminus adds
to the agent's call path, which is the claim made in the pitch deck. The deployed HTTP
round-trip (with a running server and real network) is measured separately and reported
under "Deployed HTTP latency" in the artifacts; it is not used in the gate.

## Running It

### In-process (default, no server needed)

```bash
PYTHONPATH=src uv run python -m pov.harness
```

Expected wall-clock: a few seconds. Writes artifacts to `pov/out/`.

### With a deployed-latency sweep

Start Terminus first:

```bash
PYTHONPATH=src uv run uvicorn terminus.main:app --port 8000
```

Then run the harness with `--url` to add the load sweep:

```bash
PYTHONPATH=src uv run python -m pov.harness --url http://localhost:8000
```

The default sweep is 50, 100, and 200 QPS for 20 seconds each. Expected wall-clock:
roughly 2 to 4 minutes. Use `--qps` and `--seconds` to adjust:

```bash
PYTHONPATH=src uv run python -m pov.harness \
  --url http://localhost:8000 \
  --qps 50,100 \
  --seconds 10
```

### Options

```
--out DIR       Output directory for artifacts (default: pov/out)
--url URL       Running Terminus base URL for the deployed-latency sweep
--qps LIST      Comma-separated QPS targets (default: 50,100,200)
--seconds N     Seconds per QPS step (default: 20)
```

## Artifacts

Written to `--out` (default `pov/out/`):

- `pov_report.md`: human-readable verdict, criteria table, self-correction breakdown,
  latency summary, and signal-vs-noise section.
- `latency_stats.json`: raw percentiles for in-process and deployed latency.
- `blocked_and_remediated_examples.md`: list of queries that were blocked and then
  successfully self-corrected.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All hard criteria passed |
| 1 | One or more criteria failed (named in `pov_report.md`) |

A non-zero exit means a real gate failure. The failing criteria are printed to stdout
and listed in `pov_report.md`. Do not loosen thresholds to make it green: fix the
corpus tagging or the corrector rule instead.

## CI Integration

The harness can be wired into CI as a regression gate:

```yaml
- name: Run PoV harness
  run: PYTHONPATH=src uv run python -m pov.harness
```

A non-zero exit will fail the CI step. The artifacts are available as build outputs
for review.

## Corpus

The validation corpus is `pov/corpus.yaml`: approximately 230 tagged SQL entries
covering benign reads, benign writes, destructive DDL, dangerous DML, injection
patterns, hallucinated tables, column violations, multi-statement queries, and invalid
SQL. Each entry is tagged with the expected decision against the shipped example policy
and schema whitelist (`examples/policy.yaml` and `examples/schema_whitelist.yaml`).
