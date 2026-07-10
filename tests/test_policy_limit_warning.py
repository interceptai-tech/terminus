"""Half-wired config gets an honest label (GAPS L3, spec section 5).

max_queries_per_minute is parsed but never enforced; the governance snapshot
build (boot AND hot-reload path) must warn once per offending rule so an
operator cannot mistake it for an active control.
"""

from __future__ import annotations

from structlog.testing import capture_logs

from terminus.auth.__main__ import main as auth_cli_main
from terminus.config.governance import build_policy_engine

# Real SchemaWhitelist shape (see examples/schema_whitelist.yaml): flat
# `tables` list, not the nested `schemas` mapping the original draft used.
_WHITELIST = {"version": "1.0", "enabled": True, "tables": ["public.users"]}


def _policy(limits: dict[str, object] | None) -> dict[str, object]:
    # Real PolicyRule requires `id` AND `name` (no `description` field), and
    # PolicyMatch's operation key is singular `operation`, not `operations`.
    rule: dict[str, object] = {
        "id": "allow_reads",
        "name": "reads",
        "action": "allow",
        "match": {"operation": ["SELECT"]},
    }
    if limits is not None:
        rule["limits"] = limits
    return {"version": "1.0", "default_action": "deny", "policies": [rule]}


def test_unenforced_limit_warns_once_per_rule() -> None:
    with capture_logs() as logs:
        build_policy_engine(_policy({"max_queries_per_minute": 100}), _WHITELIST)
    events = [e for e in logs if e["event"] == "policy_limit_not_enforced"]
    assert len(events) == 1
    assert events[0]["policy_id"] == "allow_reads"
    assert events[0]["limit"] == "max_queries_per_minute"


def test_enforced_limit_field_does_not_warn() -> None:
    with capture_logs() as logs:
        build_policy_engine(_policy({"max_destructive_risk_score": 0.5}), _WHITELIST)
    assert not [e for e in logs if e["event"] == "policy_limit_not_enforced"]


def test_no_limits_no_warning() -> None:
    with capture_logs() as logs:
        build_policy_engine(_policy(None), _WHITELIST)
    assert not [e for e in logs if e["event"] == "policy_limit_not_enforced"]


def test_cli_stdout_is_only_the_token_warning_goes_to_stderr(
    monkeypatch, capsys, reset_auth_caches
) -> None:
    """The operator flow TOKEN=$(python -m terminus.auth issue ...) must stay clean.

    The shipped examples/policy.yaml has a rule with max_queries_per_minute, so
    the governance build inside the CLI fires policy_limit_not_enforced. The CLI
    never configures logging, so structlog's default logger prints; the CLI must
    route that to stderr and keep stdout as exactly one line, the token.
    """
    monkeypatch.setenv("TERMINUS_JWT_SECRET", "unit-test-secret-that-is-at-least-32-bytes-long")
    # Defaults already point at examples/*; pin the registry path anyway so the
    # test does not depend on ambient TERMINUS_* env.
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", "examples/agents.yaml")
    monkeypatch.setenv("TERMINUS_POLICY_PATH", "examples/policy.yaml")
    monkeypatch.setenv("TERMINUS_SCHEMA_WHITELIST_PATH", "examples/schema_whitelist.yaml")
    reset_auth_caches()

    rc = auth_cli_main(["issue", "--agent", "analytics_agent_42"])
    assert rc == 0

    captured = capsys.readouterr()
    stdout_lines = captured.out.splitlines()
    assert len(stdout_lines) == 1  # exactly the token, nothing else
    assert stdout_lines[0].count(".") == 2  # JWT shape: header.payload.signature
    assert "policy_limit_not_enforced" not in captured.out
    assert "policy_limit_not_enforced" in captured.err
