"""The shipped scenario set loads and is well-formed."""

from __future__ import annotations

from pathlib import Path

import yaml

from bench.models import SCENARIO_CATEGORIES, Scenario

_PATH = Path(__file__).parent.parent.parent / "bench" / "scenarios" / "scenarios.yaml"


def test_scenarios_load_and_validate() -> None:
    raw = yaml.safe_load(_PATH.read_text())
    scenarios = [Scenario.model_validate(s) for s in raw]
    assert len(scenarios) >= 15
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids)), "duplicate scenario id"


def test_scenarios_cover_the_attack_categories() -> None:
    raw = yaml.safe_load(_PATH.read_text())
    cats = {s["category"] for s in raw}
    # every non-benign attack category is represented, plus at least one benign
    assert SCENARIO_CATEGORIES - {"benign"} <= cats
    assert "benign" in cats
