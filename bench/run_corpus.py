"""Third-party SQLi corpus as an INDEPENDENT-GROUND-TRUTH DIFFERENTIAL ORACLE.

Earlier framing (a single "executed-rate" over payloads sent as standalone
statements under an UNREGISTERED agent) was wrong twice over: every request
died at the authorization layer, so the 0% was an authz artifact, not a
parser-abuse result; and a raw block/execute rate can be gamed by a
tautology-on-an-allowed-table counterexample. This module replaces it.

Methodology
-----------
1. Authorized agent. Every payload is evaluated under ``analytics_agent_42``,
   which matches ``allow_analytics_reads`` in examples/policy.yaml (agent_ids
   ``analytics_agent_*``). So the ONLY thing standing between a payload and the
   database is Terminus's parse/whitelist/column/injection analysis, not a
   missing registration. The unregistered agent is kept ONLY as an optional
   control row (it denies everything at authz); it is never a security number.

2. Injection framing. Each libinjection line is URL-decoded (unquote_plus) and
   composed INTO a legitimate analytics SELECT, landing in a value, predicate,
   or identifier position, exactly where a naive app would splice user input.
   Templates (documented, applied as a cross-product so each payload is tried
   in every position):
     - "SELECT id, name FROM public.users WHERE id = {payload}"     (numeric predicate)
     - "SELECT id, name FROM public.users WHERE name = '{payload}'" (string predicate)
     - "SELECT {payload} FROM public.users"                         (projection / identifier)
   The COMPOSED string is what is sent to /intercept and what the labeler parses.

3. Independent ground truth (the crux). ``ground_truth(composed_sql)`` is
   computed from the sqlglot PARSE TREE plus the static config read straight
   from examples/schema_whitelist.yaml and examples/policy.yaml. It does NOT
   call ``terminus.policy`` and never reads Terminus's decision or reason_code,
   so it is a genuinely independent oracle, not a mirror of the thing under
   test. A composed statement is GT_DENY if it: fails to parse, is not exactly
   one statement, is not a plain SELECT (any write / destructive op), references
   a table not on the whitelist, reads a column outside the allowlist of a
   restricted table (public.users is restricted to [id, name, email], and a
   wildcard over it reads restricted columns), or invokes an injection-list
   function. Otherwise GT_ALLOW (a valid, in-scope SELECT).

4. Metrics (confusion matrix, replacing the old executed-rate headline):
     - containment    = deny-rate over GT_DENY payloads (target 100%)
     - FALSE_ALLOWS   = GT_DENY payloads Terminus ALLOWED (THE HEADLINE, target 0;
                        one leak moves it -> falsifiable; a nonzero value is a
                        real Terminus finding, reported loudly, never papered over)
     - errors         = 500s / crashes / any non-allow-non-deny outcome (target 0)
     - in_scope_allows= allow-rate over GT_ALLOW (expected and CORRECT, not a miss:
                        Terminus enforces scope, not intent, so an in-scope
                        tautology on an allowed table is allowed by design)
   Written to bench/out/corpus_oracle.json.

The Terminus side reuses the shipped decision path through FastAPI TestClient
(same pattern as bench/run_static.py and pov/harness.py). An error is anything
that is not a clean allow/deny (missing decision, exception, non-JSON); it is
counted as an error, NOT silently folded into deny.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import unquote_plus

import sqlglot
import yaml
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from terminus.config.settings import get_settings
from terminus.main import app

GT_DENY = "GT_DENY"
GT_ALLOW = "GT_ALLOW"

_AUTHORIZED_AGENT = "analytics_agent_42"  # matches allow_analytics_reads in policy.yaml
_UNAUTHORIZED_AGENT = "bench_corpus_agent"  # control only: denies at authz, never reported

_REPO_ROOT = Path(__file__).resolve().parent.parent
_WHITELIST_PATH = _REPO_ROOT / "examples" / "schema_whitelist.yaml"
_POLICY_PATH = _REPO_ROOT / "examples" / "policy.yaml"
_CORPUS_DIR = Path(__file__).resolve().parent / "corpora" / "libinjection"
_OUT_PATH = Path(__file__).resolve().parent / "out" / "corpus_oracle.json"

# Injection / time-based / RCE function names. Defined here (not imported from
# terminus) to keep the oracle independent of the code under test; it mirrors the
# well-known dangerous-function set an analytics read must never invoke.
_INJECTION_FUNCTIONS = frozenset(
    {
        "pg_sleep",
        "sleep",
        "benchmark",
        "waitfor",
        "xp_cmdshell",
        "sp_executesql",
        "exec",
        "execute",
        "load_file",
        "pg_read_file",
        "pg_ls_dir",
        "dblink",
        "pg_terminate_backend",
        "pg_cancel_backend",
    }
)

# Injection templates: {payload} lands in a numeric predicate, a string
# predicate, and a projection/identifier position of a legitimate analytics read.
INJECTION_TEMPLATES: tuple[str, ...] = (
    "SELECT id, name FROM public.users WHERE id = {payload}",
    "SELECT id, name FROM public.users WHERE name = '{payload}'",
    "SELECT {payload} FROM public.users",
)

# Trusted normalization dialect: mirror the shipped parser, which pins identifier
# folding to the deployment dialect (empty default -> sqlglot default dialect).
_DIALECT = get_settings().sql_dialect or None


class Whitelist(BaseModel):
    """The static schema whitelist, loaded from examples/schema_whitelist.yaml."""

    table_globs: list[str]  # lowercased "schema.table" patterns, e.g. "analytics.*"
    restricted_columns: dict[str, frozenset[str]]  # table -> allowed column set

    model_config = {"arbitrary_types_allowed": True}


def load_whitelist(path: Path = _WHITELIST_PATH) -> Whitelist:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    globs: list[str] = []
    restricted: dict[str, frozenset[str]] = {}
    for item in raw.get("tables", []):
        if isinstance(item, str):
            globs.append(item.lower())
        elif isinstance(item, dict):
            for name, spec in item.items():
                globs.append(str(name).lower())
                cols = (spec or {}).get("columns") if isinstance(spec, dict) else None
                if cols:
                    restricted[str(name).lower()] = frozenset(c.lower() for c in cols)
    return Whitelist(table_globs=globs, restricted_columns=restricted)


def load_destructive_ops(path: Path = _POLICY_PATH) -> frozenset[str]:
    """Read the destructive-operation set straight from examples/policy.yaml
    (the block_all_destructive_operations rule). Informational for the labeler:
    any non-SELECT already denies, but this honors "read the policy directly"."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    ops: set[str] = set()
    for pol in raw.get("policies", []):
        if pol.get("action") == "deny":
            for op in pol.get("match", {}).get("operation", []) or []:
                ops.add(str(op).upper())
    return frozenset(ops)


def _normalize_table(table: exp.Table) -> str:
    parts = [table.catalog or None, table.db or None, table.name]
    return ".".join(str(p) for p in parts if p).lower()


def _table_allowed(table: str, globs: Sequence[str]) -> bool:
    return any(fnmatch(table, g) for g in globs)


def _function_names(stmt: exp.Expression) -> set[str]:
    names: set[str] = set()
    for node in stmt.find_all(exp.Func):
        name = node.name if isinstance(node, exp.Anonymous) else node.sql_name() or node.name
        if name:
            names.add(name.lower())
    return names


def _references_disallowed_column(
    stmt: exp.Expression, tables: Sequence[str], restricted: dict[str, frozenset[str]]
) -> bool:
    """True if the statement reads a column outside the allowlist of any
    restricted table in scope (including a wildcard over one). Conservative:
    a column that cannot be confidently attributed while a restricted table is
    present is treated as disallowed, matching a fail-closed policy."""
    restricted_in_scope = [t for t in tables if t in restricted]
    if not restricted_in_scope:
        return False

    # Alias / short-name -> normalized table, so qualified columns can be resolved.
    alias_map: dict[str, str] = {}
    for table in stmt.find_all(exp.Table):
        norm = _normalize_table(table)
        if not norm:
            continue
        alias_map[norm] = norm
        if table.name:
            alias_map[table.name.lower()] = norm
        if table.alias:
            alias_map[table.alias.lower()] = norm

    single_table = tables[0] if len(tables) == 1 else None

    # Bare wildcard (SELECT *) that is not an aggregate arg reads every column.
    for star in stmt.find_all(exp.Star):
        if star.find_ancestor(exp.Func) is not None:
            continue  # COUNT(*) leaks no column values
        if isinstance(star.parent, exp.Column):
            continue  # qualified t.* handled below
        return True  # bare star while a restricted table is in scope

    for column in stmt.find_all(exp.Column):
        name = column.name.lower()
        qualifier = (column.table or "").lower() or None
        if name == "*":
            if column.find_ancestor(exp.Func) is not None:
                continue
            target = alias_map.get(qualifier) if qualifier else None
            if target in restricted:
                return True  # t.* over a restricted table
            if target is None:
                return True  # unresolvable wildcard while restricted table present
            continue
        # unqualified: attribute to the sole table if any
        target = alias_map.get(qualifier) if qualifier is not None else single_table
        if target is None:
            return True  # cannot attribute + restricted table in scope -> fail closed
        if target in restricted and name not in restricted[target]:
            return True
    return False


def ground_truth(
    composed_sql: str,
    *,
    whitelist: Whitelist | None = None,
    dialect: str | None = _DIALECT,
) -> str:
    """Independent label for a composed statement: GT_DENY or GT_ALLOW.

    Computed from the sqlglot parse tree + the static whitelist/policy config.
    Never consults terminus.policy or a Terminus decision.
    """
    wl = whitelist if whitelist is not None else load_whitelist()
    try:
        parsed = sqlglot.parse(composed_sql, read=dialect)
    except SqlglotError:
        return GT_DENY  # unparseable
    except Exception:  # any other sqlglot internal failure -> fail closed
        return GT_DENY

    statements = [e for e in parsed if e is not None]
    if len(statements) != 1:
        return GT_DENY  # multi-statement (or empty)

    try:
        stmt = normalize_identifiers(statements[0], dialect=dialect)
    except Exception:
        return GT_DENY

    if not isinstance(stmt, exp.Select):
        return GT_DENY  # not a plain SELECT (a write / destructive / DDL statement)

    if _function_names(stmt) & _INJECTION_FUNCTIONS:
        return GT_DENY

    tables = sorted({_normalize_table(t) for t in stmt.find_all(exp.Table) if t.name})
    for table in tables:
        if not _table_allowed(table, wl.table_globs):
            return GT_DENY

    if _references_disallowed_column(stmt, tables, wl.restricted_columns):
        return GT_DENY

    return GT_ALLOW


def compose(payload: str) -> list[str]:
    """Compose one decoded payload into every injection template."""
    return [tmpl.format(payload=payload) for tmpl in INJECTION_TEMPLATES]


def load_payloads(corpus_dir: Path = _CORPUS_DIR) -> list[str]:
    """Decoded payload lines from every *.txt in corpus_dir (skip blanks / #)."""
    payloads: list[str] = []
    for path in sorted(corpus_dir.glob("*.txt")):
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            payloads.append(unquote_plus(line))
    return payloads


def executed_rate(decisions: Sequence[str]) -> float:
    """Fraction of decisions that were ALLOWED. Kept as an internal helper /
    sanity number; the reported artifact is the confusion matrix, not this."""
    if not decisions:
        return 0.0
    return sum(1 for d in decisions if d == "allow") / len(decisions)


class OracleMatrix(BaseModel):
    """Differential confusion matrix: independent ground truth vs Terminus."""

    total: int
    gt_deny_total: int
    gt_allow_total: int
    contained: int  # GT_DENY and Terminus denied
    false_allows: int  # GT_DENY and Terminus ALLOWED -- the headline (target 0)
    gt_deny_errors: int  # GT_DENY and Terminus errored
    errors: int  # any row with a non-allow-non-deny outcome (target 0)
    in_scope_allows: int  # GT_ALLOW and Terminus allowed (expected, correct)
    in_scope_denies: int  # GT_ALLOW and Terminus denied (safe over-block, informational)
    containment_rate: float  # contained / gt_deny_total
    in_scope_allow_rate: float  # in_scope_allows / gt_allow_total


def aggregate(rows: Sequence[tuple[str, str]]) -> OracleMatrix:
    """rows: (gt_label, terminus_decision in {allow, deny, error})."""
    gt_deny_total = sum(1 for gt, _ in rows if gt == GT_DENY)
    gt_allow_total = sum(1 for gt, _ in rows if gt == GT_ALLOW)
    contained = sum(1 for gt, d in rows if gt == GT_DENY and d == "deny")
    false_allows = sum(1 for gt, d in rows if gt == GT_DENY and d == "allow")
    gt_deny_errors = sum(1 for gt, d in rows if gt == GT_DENY and d == "error")
    errors = sum(1 for _, d in rows if d == "error")
    in_scope_allows = sum(1 for gt, d in rows if gt == GT_ALLOW and d == "allow")
    in_scope_denies = sum(1 for gt, d in rows if gt == GT_ALLOW and d == "deny")
    return OracleMatrix(
        total=len(rows),
        gt_deny_total=gt_deny_total,
        gt_allow_total=gt_allow_total,
        contained=contained,
        false_allows=false_allows,
        gt_deny_errors=gt_deny_errors,
        errors=errors,
        in_scope_allows=in_scope_allows,
        in_scope_denies=in_scope_denies,
        containment_rate=(contained / gt_deny_total) if gt_deny_total else 1.0,
        in_scope_allow_rate=(in_scope_allows / gt_allow_total) if gt_allow_total else 1.0,
    )


def _terminus_decision(client: TestClient, sql: str, agent_id: str) -> str:
    """Clean allow/deny, or 'error' for anything else (missing decision, non-JSON,
    exception). Errors are NOT folded into deny -- they are their own tracked bucket."""
    try:
        resp = client.post("/intercept", json={"sql": sql, "dialect": None, "agent_id": agent_id})
        body = resp.json()
    except Exception:
        return "error"
    decision = body.get("decision")
    if decision in ("allow", "deny"):
        return str(decision)
    return "error"


def run_oracle(
    payloads: Sequence[str] | None = None,
    *,
    include_control: bool = True,
) -> tuple[OracleMatrix, dict[str, object]]:
    """Compose every payload x template, label each independently, then compare
    against Terminus under the AUTHORIZED agent. Returns (matrix, control_info)."""
    wl = load_whitelist()
    lines = list(payloads) if payloads is not None else load_payloads()
    composed = [c for payload in lines for c in compose(payload)]
    labels = [ground_truth(c, whitelist=wl) for c in composed]

    with TestClient(app) as client:
        decisions = [_terminus_decision(client, c, _AUTHORIZED_AGENT) for c in composed]
        control: dict[str, object] = {}
        if include_control:
            control_decisions = [
                _terminus_decision(client, c, _UNAUTHORIZED_AGENT) for c in composed
            ]
            control = {
                "agent_id": _UNAUTHORIZED_AGENT,
                "total": len(control_decisions),
                "deny_rate": 1.0 - executed_rate(control_decisions),
                "note": (
                    "Unregistered/unauthorized agent: everything denies at the "
                    "authorization layer. This is a wiring sanity check ONLY, not a "
                    "parser-abuse security number."
                ),
            }

    matrix = aggregate(list(zip(labels, decisions, strict=True)))
    return matrix, control


def main() -> int:
    if not _CORPUS_DIR.is_dir() or not any(_CORPUS_DIR.glob("*.txt")):
        print(
            "bench/corpora/libinjection/ is empty or missing. "
            "Run `make bench-fetch` first to download the pinned corpus.",
            file=sys.stderr,
        )
        return 1

    matrix, control = run_oracle()

    print("Third-party SQLi corpus: independent-ground-truth differential oracle")
    print(f"  authorized agent:     {_AUTHORIZED_AGENT}")
    print(
        f"  composed statements:  {matrix.total}  "
        f"(payloads x {len(INJECTION_TEMPLATES)} templates)"
    )
    print(f"  ground-truth DENY:    {matrix.gt_deny_total}")
    print(f"  ground-truth ALLOW:   {matrix.gt_allow_total}")
    print(
        f"  containment:          {matrix.containment_rate:.4%}  "
        "(deny-rate over GT_DENY; target 100%)"
    )
    print(f"  FALSE_ALLOWS:         {matrix.false_allows}  <== HEADLINE (target 0)")
    print(f"  errors:               {matrix.errors}  (target 0)")
    print(
        f"  in-scope allow-rate:  {matrix.in_scope_allow_rate:.4%}  "
        "(GT_ALLOW allowed; expected/correct)"
    )
    print(
        f"  in-scope over-blocks: {matrix.in_scope_denies}  "
        "(GT_ALLOW denied; safe, informational)"
    )
    if control:
        print(
            f"  [control] {control['agent_id']} deny-rate: "
            f"{control['deny_rate']:.4%} (authz sanity only)"
        )

    if matrix.false_allows > 0:
        print(
            f"  WARNING: {matrix.false_allows} GT_DENY payload(s) were ALLOWED by Terminus. "
            "This is a real finding, not an oracle artifact until proven otherwise.",
            file=sys.stderr,
        )

    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = matrix.model_dump()
    report["authorized_agent"] = _AUTHORIZED_AGENT
    report["templates"] = list(INJECTION_TEMPLATES)
    report["control_unauthorized_agent"] = control
    _OUT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {_OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
