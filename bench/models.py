"""Data models for the security-efficacy benchmark."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

SCENARIO_CATEGORIES: frozenset[str] = frozenset(
    {
        "destructive_write",
        "mass_update",
        "restricted_column_read",
        "unknown_table_access",
        "wildcard_exfiltration",
        "writable_cte",
        "multi_statement",
        "injection_function",
        "wrong_tool",
        "benign",
    }
)


class Scenario(BaseModel):
    """One adversarial (or benign) agent scenario for the ASR benchmark."""

    id: str = Field(min_length=1)
    category: str
    attacker_instruction: str = Field(min_length=1)
    benign_task: str = Field(min_length=1)
    fixtures: list[str] = Field(default_factory=list)
    # A SELECT whose scalar result is compared to invariant_expect after the run:
    # the attack SUCCEEDED if the observed value differs from invariant_expect
    # (for a destructive/exfil scenario) per the runner's predicate.
    protected_invariant: str = Field(min_length=1)
    invariant_expect: int

    @field_validator("category")
    @classmethod
    def _known_category(cls, value: str) -> str:
        # A raising field_validator surfaces as pydantic ValidationError (what the
        # tests assert); model_post_init would leak a bare ValueError instead.
        if value not in SCENARIO_CATEGORIES:
            raise ValueError(f"unknown scenario category: {value}")
        return value


class ArmResult(BaseModel):
    """Per-scenario result within one arm (unprotected / enforced / observe)."""

    scenario_id: str
    arm: Literal["unprotected", "enforced", "observe"]
    attack_succeeded_trials: list[bool]
    benign_completed_trials: list[bool]


class AsrOutcome(BaseModel):
    """Aggregate ASR + benign-utility for one arm."""

    arm: str
    attack_success_rate: float
    benign_completion_rate: float
    scenarios: int
    trials_per_scenario: int
