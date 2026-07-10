"""Reload-time trust diff: changed agents and new observe agents emit events."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from terminus.audit.audit_logger import configure_logging
from terminus.auth.registry import AgentEntry, AgentRegistry
from terminus.config.governance import _trust_changes, get_governance_manager


def _reg(*entries: AgentEntry) -> AgentRegistry:
    return AgentRegistry(agents=list(entries))


def test_promotion_and_demotion_detected() -> None:
    old = _reg(AgentEntry(id="a", trust_level="observe"), AgentEntry(id="b"))
    new = _reg(AgentEntry(id="a", trust_level="enforce"), AgentEntry(id="b", trust_level="observe"))
    changes = _trust_changes(old, new)
    assert ("a", "observe", "enforce") in [(c[0], c[1], c[2]) for c in changes]
    assert ("b", "enforce", "observe") in [(c[0], c[1], c[2]) for c in changes]


def test_new_observe_agent_is_a_change_from_unregistered() -> None:
    old = _reg()
    new = _reg(AgentEntry(id="fresh", trust_level="observe"))
    changes = _trust_changes(old, new)
    assert [(c[0], c[1], c[2]) for c in changes] == [("fresh", "unregistered", "observe")]


def test_new_enforce_agent_and_no_change_emit_nothing() -> None:
    old = _reg(AgentEntry(id="steady", trust_level="observe"))
    new = _reg(AgentEntry(id="steady", trust_level="observe"), AgentEntry(id="fresh2"))
    assert _trust_changes(old, new) == []


def test_disabled_observe_reactivated_is_enforce_to_observe() -> None:
    # F-final #2: a disabled,observe agent's EFFECTIVE trust is enforce
    # (AgentRegistry.trust_of only honors trust_level when status == active).
    # Flipping it to active,observe silently strengthens... no, WEAKENS
    # enforcement (enforce -> observe) with no signed event under the old
    # raw-trust_level diff, since trust_level itself never changed.
    old = _reg(AgentEntry(id="x", status="disabled", trust_level="observe"))
    new = _reg(AgentEntry(id="x", status="active", trust_level="observe"))
    changes = _trust_changes(old, new)
    assert [(c[0], c[1], c[2]) for c in changes] == [("x", "enforce", "observe")]


def test_adding_disabled_observe_agent_emits_nothing() -> None:
    # A brand-new agent added as disabled,observe has effective trust enforce
    # (same as unregistered), so this must NOT emit a spurious
    # unregistered->observe promotion event.
    old = _reg()
    new = _reg(AgentEntry(id="y", status="disabled", trust_level="observe"))
    assert _trust_changes(old, new) == []


def test_disabling_active_observe_agent_is_observe_to_enforce() -> None:
    # Disabling an active observe agent (trust_level left untouched) is a real
    # enforcement tightening -- observe -> enforce -- worth recording, even
    # though the raw trust_level field never changed.
    old = _reg(AgentEntry(id="z", status="active", trust_level="observe"))
    new = _reg(AgentEntry(id="z", status="disabled", trust_level="observe"))
    changes = _trust_changes(old, new)
    assert [(c[0], c[1], c[2]) for c in changes] == [("z", "observe", "enforce")]


def test_reload_now_emits_signed_trust_change_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reset_auth_caches,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """End to end: promoting onboarding_agent_9 to enforce on disk and reloading
    emits one terminus_trust_level_change line carrying previous_trust_level."""
    examples = Path(__file__).parent.parent / "examples"
    policy_path = tmp_path / "policy.yaml"
    whitelist_path = tmp_path / "schema_whitelist.yaml"
    agents_path = tmp_path / "agents.yaml"
    shutil.copy(examples / "policy.yaml", policy_path)
    shutil.copy(examples / "schema_whitelist.yaml", whitelist_path)
    shutil.copy(examples / "agents.yaml", agents_path)

    monkeypatch.setenv("TERMINUS_POLICY_PATH", str(policy_path))
    monkeypatch.setenv("TERMINUS_SCHEMA_WHITELIST_PATH", str(whitelist_path))
    monkeypatch.setenv("TERMINUS_AGENT_REGISTRY_PATH", str(agents_path))
    reset_auth_caches()
    configure_logging()

    manager = get_governance_manager()  # builds initial snapshot: onboarding_agent_9 = observe
    assert manager.snapshot.registry.trust_of("onboarding_agent_9") == "observe"

    agents_text = agents_path.read_text(encoding="utf-8")
    agents_path.write_text(
        agents_text.replace("trust_level: observe", "trust_level: enforce"), encoding="utf-8"
    )

    assert manager.reload_now() == "applied"

    lines = [ln for ln in capsys.readouterr().out.strip().splitlines() if ln]
    trust_events = [
        json.loads(ln)
        for ln in lines
        if "terminus_trust_level_change" in ln and "onboarding_agent_9" in ln
    ]
    assert len(trust_events) == 1
    assert trust_events[0]["previous_trust_level"] == "observe"
    assert trust_events[0]["new_trust_level"] == "enforce"
