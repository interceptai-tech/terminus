"""Agent registry: the set of agent identities Terminus will accept."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentEntry(BaseModel):
    """One registered agent.

    extra="ignore" deliberately accepts reserved forward-compat metadata
    (e.g. policy_profile, rate_limit_tier, owner): accepted and ignored by
    design, no behavior today. id, status, and trust_level (graduated
    autonomy) are the fields live behavior depends on.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    description: str | None = None
    status: Literal["active", "disabled"] = "active"
    # Graduated autonomy. enforce is the fail-safe default: "starts observe-only"
    # is an OPERATOR action (they write trust_level: observe), never a code default.
    trust_level: Literal["observe", "enforce"] = "enforce"
    # Optional promotion provenance, recorded in the signed trust-change audit
    # event when present; git history is the authorship fallback.
    trust_changed_by: str | None = None
    trust_change_reason: str | None = None


class AgentRegistry(BaseModel):
    """Default-deny allow-list of agent identities, loaded from agents.yaml."""

    model_config = ConfigDict(extra="forbid")

    version: str = "1.0"
    agents: list[AgentEntry] = Field(default_factory=list)

    def is_active(self, agent_id: str) -> bool:
        """True only if the agent is present and not disabled."""
        return any(a.id == agent_id and a.status == "active" for a in self.agents)

    def trust_of(self, agent_id: str) -> Literal["observe", "enforce"]:
        """Effective trust for an agent. Enforce for unknown, disabled, or unset.

        Observe WEAKENS enforcement, so every ambiguous case resolves to enforce:
        a typo'd id, a removed entry, or a disabled agent can never soften a deny.
        """
        for agent in self.agents:
            if agent.id == agent_id:
                return agent.trust_level if agent.status == "active" else "enforce"
        return "enforce"


def get_registry() -> AgentRegistry:
    """Return the current agent registry from the governance snapshot."""
    # Deferred import avoids a cycle (governance imports this module).
    from terminus.config.governance import get_governance_manager

    return get_governance_manager().snapshot.registry
