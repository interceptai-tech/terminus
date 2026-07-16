"""Snowflake side-effecting functions must be denied when smuggled into an
otherwise-allowed read; benign SYSTEM$ introspection must stay allowed.

Candidate classification (verified via the `_function_name` probe before
being added to `INJECTION_FUNCTION_NAMES`):

Dangerous Snowflake side-effecting functions, confirmed to resolve to a
stable, matchable `_function_name` under both the `snowflake` dialect and
the default/empty dialect (dialect-agnostic, as the denylist itself is):
`system$wait` (time-based / DoS, the `pg_sleep` analogue),
`system$abort_session`, `system$abort_transaction`, `system$cancel_query`,
`system$cancel_all_queries`, `system$wait_for_services` (time-based / DoS,
same class as `system$wait`), and the notification side-channels
`system$send_email` / `system$send_snowflake_notification` (an agent could
exfiltrate data or spam an external recipient without ever writing to a
whitelisted table).

Explicitly NOT added (benign introspection -- a blanket `system$*` deny
would false-positive): `system$clustering_information`,
`system$clustering_depth`, `system$typeof`, `system$pipe_status`,
`system$whitelist`, `system$get_privatelink_config`. These must remain
ALLOWED when they appear in an otherwise-allowed read.

Deferred, not added to the denylist: `system$enable_behavior_change_bundle`,
`system$disable_behavior_change_bundle`,
`system$generate_scim_access_token`,
`system$user_task_cancel_ongoing_executions`, `system$set_return_value`,
`system$log` -- lower-priority side-effecting SYSTEM$ functions deliberately
deferred; the denylist is intentionally non-exhaustive atop the
default-deny/whitelist core.

Statement-type threats the function denylist structurally CANNOT see
(documented, not added here -- covered by default-deny / whitelist):
`CALL` (Command), `EXECUTE IMMEDIATE` (Command), `EXECUTE TASK` (Command),
`COPY INTO <stage>` (Copy).

See docs/superpowers/plans/2026-07-15-snowflake-validation.md Task 2 for the
full candidate classification.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyConfig, PolicyEngine, SchemaWhitelist

_ROOT = pathlib.Path("examples")
_AGENT = "analytics_agent_42"


def _engine() -> PolicyEngine:
    pol = PolicyConfig.model_validate(
        yaml.safe_load((_ROOT / "policy.yaml").read_text()), context={"dialect": "snowflake"}
    )
    wl = SchemaWhitelist.model_validate(
        yaml.safe_load((_ROOT / "schema_whitelist.yaml").read_text()),
        context={"dialect": "snowflake"},
    )
    return PolicyEngine(pol, whitelist=wl, enforce_injection=True)


DANGEROUS = [
    "SELECT id FROM public.users WHERE id = SYSTEM$WAIT(5)",
    "SELECT id FROM public.users WHERE id = SYSTEM$ABORT_SESSION(1)",
    "SELECT id FROM public.users WHERE id = SYSTEM$ABORT_TRANSACTION(1)",
    "SELECT id FROM public.users WHERE id = SYSTEM$CANCEL_QUERY('q')",
    "SELECT id FROM public.users WHERE id = SYSTEM$CANCEL_ALL_QUERIES(1)",
    "SELECT id FROM public.users WHERE id = SYSTEM$WAIT_FOR_SERVICES(300, 'svc')",
    "SELECT id FROM public.users WHERE id = SYSTEM$SEND_EMAIL('int_name', 'a@b.com', 'subj', 'body')",
    "SELECT id FROM public.users WHERE id = SYSTEM$SEND_SNOWFLAKE_NOTIFICATION('t', 'b')",
]

BENIGN = [
    "SELECT id FROM public.users WHERE id = SYSTEM$TYPEOF(id)",
    "SELECT id FROM public.users WHERE id = SYSTEM$CLUSTERING_DEPTH('public.users')",
]


@pytest.mark.parametrize("sql", DANGEROUS)
def test_dangerous_snowflake_functions_denied(sql: str) -> None:
    d = _engine().evaluate(parse_sql(sql, dialect="snowflake"), agent_id=_AGENT)
    assert d.action == "deny"
    assert d.reason_code == "injection_function"


@pytest.mark.parametrize("sql", BENIGN)
def test_benign_system_functions_allowed(sql: str) -> None:
    d = _engine().evaluate(parse_sql(sql, dialect="snowflake"), agent_id=_AGENT)
    assert d.action == "allow"


def test_denylist_is_dialect_agnostic() -> None:
    """A dangerous SYSTEM$ call must still be denied when the statement is
    parsed with the default/empty dialect, not just `snowflake`: the
    `_function_name` resolution that the denylist matches against does not
    depend on parse grammar. `normalize_dialect="snowflake"` is passed
    explicitly here only to match this fixture's whitelist-normalization
    context (see `_engine`), so the schema-whitelist gate upstream of the
    injection-function gate does not itself deny first for an unrelated
    reason; the parse `dialect` -- the thing actually under test -- is left
    at its default.
    """
    sql = "SELECT id FROM public.users WHERE id = SYSTEM$WAIT(5)"
    d = _engine().evaluate(parse_sql(sql, normalize_dialect="snowflake"), agent_id=_AGENT)
    assert d.action == "deny"
    assert d.reason_code == "injection_function"


def test_casing_evasion_denied() -> None:
    """Mixed/inverted casing on the function name must not evade the
    denylist. `_function_name` lowercases the resolved identifier before
    the membership check, so `SyStEm$WaIt` matches the `system$wait` entry
    exactly like the canonically-cased call.
    """
    sql = "SELECT id FROM public.users WHERE id = SyStEm$WaIt(5)"
    d = _engine().evaluate(parse_sql(sql, dialect="snowflake"), agent_id=_AGENT)
    assert d.action == "deny"
    assert d.reason_code == "injection_function"
