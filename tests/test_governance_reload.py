"""Tests for GitOps governance hot-reload: settings, metrics, manager, seam."""

from __future__ import annotations

import textwrap
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from structlog.testing import capture_logs

from terminus.auth.registry import get_registry
from terminus.config import governance as gov
from terminus.config import settings as settings_mod
from terminus.config.settings import TerminusSettings
from terminus.observability import metrics
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import get_policy_engine


def test_config_reload_interval_defaults_to_zero() -> None:
    assert TerminusSettings().config_reload_interval == 0


def test_record_config_reload_counts_and_sets_timestamp() -> None:
    before = metrics.CONFIG_RELOAD_TOTAL.labels(result="applied")._value.get()
    metrics.record_config_reload("applied")
    after = metrics.CONFIG_RELOAD_TOTAL.labels(result="applied")._value.get()
    assert after == before + 1
    assert metrics.CONFIG_LAST_RELOAD_TIMESTAMP._value.get() > 0

    # "failed"/"unchanged" count but do not touch the timestamp
    ts = metrics.CONFIG_LAST_RELOAD_TIMESTAMP._value.get()
    metrics.record_config_reload("failed")
    assert metrics.CONFIG_LAST_RELOAD_TIMESTAMP._value.get() == ts


_POLICY = """
version: "1.0"
default_action: deny
policies:
  - id: allow_users_read
    name: read users
    priority: 10
    match:
      operation: ["SELECT"]
      tables: ["public.users"]
    action: allow
"""
_WHITELIST = """
version: "1.0"
enabled: true
tables:
  - public.users
"""
_AGENTS = """
version: "1.0"
agents:
  - id: agent_a
"""


def _write_config(tmp_path: Path, policy=_POLICY, whitelist=_WHITELIST, agents=_AGENTS) -> None:
    (tmp_path / "policy.yaml").write_text(textwrap.dedent(policy), encoding="utf-8")
    (tmp_path / "whitelist.yaml").write_text(textwrap.dedent(whitelist), encoding="utf-8")
    (tmp_path / "agents.yaml").write_text(textwrap.dedent(agents), encoding="utf-8")


@pytest.fixture
def manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> gov.GovernanceConfigManager:
    _write_config(tmp_path)
    monkeypatch.setenv("TERMINUS_POLICY_PATH", str(tmp_path / "policy.yaml"))
    monkeypatch.setenv("TERMINUS_SCHEMA_WHITELIST_PATH", str(tmp_path / "whitelist.yaml"))
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", str(tmp_path / "agents.yaml"))
    settings_mod._settings = None  # force settings reload with the test paths
    gov.get_governance_manager.cache_clear()
    mgr = gov.get_governance_manager()
    yield mgr
    settings_mod._settings = None
    gov.get_governance_manager.cache_clear()


def test_combined_hash_changes_on_any_file(tmp_path: Path) -> None:
    _write_config(tmp_path)
    paths = {
        "policy": tmp_path / "policy.yaml",
        "whitelist": tmp_path / "whitelist.yaml",
        "agents": tmp_path / "agents.yaml",
    }
    h1 = gov._combined_hash(paths)
    (tmp_path / "agents.yaml").write_text(_AGENTS + "\n  - id: agent_b\n", encoding="utf-8")
    assert gov._combined_hash(paths) != h1


def test_initial_snapshot_is_frozen_and_populated(manager: gov.GovernanceConfigManager) -> None:
    snap = manager.snapshot
    assert snap.engine is not None and snap.registry is not None
    assert len(snap.version) == 64 and snap.loaded_at > 0
    with pytest.raises(FrozenInstanceError):
        snap.engine = None  # frozen dataclass


def test_reload_unchanged_is_noop(manager: gov.GovernanceConfigManager) -> None:
    before = manager.snapshot
    assert manager.reload_now() == "unchanged"
    assert manager.snapshot is before  # identity preserved, no swap


def test_reload_applied_swaps_atomically(
    manager: gov.GovernanceConfigManager, tmp_path: Path
) -> None:
    # add agent_b to the registry on disk
    (tmp_path / "agents.yaml").write_text(_AGENTS + "  - id: agent_b\n", encoding="utf-8")
    assert manager.reload_now() == "applied"
    assert manager.snapshot.registry.is_active("agent_b")


def test_invalid_config_keeps_last_known_good(
    manager: gov.GovernanceConfigManager, tmp_path: Path
) -> None:
    good = manager.snapshot
    (tmp_path / "policy.yaml").write_text("this: is: not: valid: policy", encoding="utf-8")
    assert manager.reload_now() == "failed"
    assert manager.snapshot is good  # last-known-good retained
    # the breaker still enforces the prior policy
    decision = manager.snapshot.engine.evaluate(
        parse_sql("SELECT id FROM public.users"), agent_id="agent_a"
    )
    assert decision.action == "allow"


def test_live_agent_revocation(manager: gov.GovernanceConfigManager, tmp_path: Path) -> None:
    assert manager.snapshot.registry.is_active("agent_a")
    (tmp_path / "agents.yaml").write_text(
        textwrap.dedent("""
            version: "1.0"
            agents:
              - id: agent_a
                status: disabled
            """),
        encoding="utf-8",
    )
    assert manager.reload_now() == "applied"
    assert not manager.snapshot.registry.is_active("agent_a")


def test_seam_reflects_current_snapshot(
    manager: gov.GovernanceConfigManager, tmp_path: Path
) -> None:
    assert get_policy_engine() is manager.snapshot.engine
    assert get_registry() is manager.snapshot.registry
    (tmp_path / "agents.yaml").write_text(_AGENTS + "  - id: agent_b\n", encoding="utf-8")
    assert manager.reload_now() == "applied"
    # after a swap, the getters return the NEW instances
    assert get_policy_engine() is manager.snapshot.engine
    assert get_registry() is manager.snapshot.registry
    assert get_registry().is_active("agent_b")


def test_reload_warns_on_newly_added_unenforced_limit(
    manager: gov.GovernanceConfigManager, tmp_path: Path
) -> None:
    # GAPS L3: a hot-reload that introduces max_queries_per_minute must warn,
    # not just the boot path build_policy_engine also runs on.
    policy_with_limit = _POLICY.replace(
        "    action: allow\n",
        "    action: allow\n    limits:\n      max_queries_per_minute: 100\n",
    )
    (tmp_path / "policy.yaml").write_text(textwrap.dedent(policy_with_limit), encoding="utf-8")
    with capture_logs() as logs:
        assert manager.reload_now() == "applied"
    events = [e for e in logs if e["event"] == "policy_limit_not_enforced"]
    assert len(events) == 1
    assert events[0]["policy_id"] == "allow_users_read"
    assert events[0]["limit"] == "max_queries_per_minute"


def test_off_builds_once_no_poll(manager: gov.GovernanceConfigManager) -> None:
    # interval defaults to 0: the manager has a snapshot, and run_config_poll_loop
    # is only ever started by the lifespan when interval > 0 (asserted by reading
    # the lifespan); here we assert the manager is usable with no background task.
    assert manager.snapshot.version
    # reload_now is callable directly (tests/admin) even when polling is off
    assert manager.reload_now() == "unchanged"
