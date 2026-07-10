"""GitOps hot-reload of the governance config (policy + whitelist + registry).

Reads the three governance files from the configured settings paths and holds
them as one immutable GovernanceSnapshot, swapped atomically. reload_now()
validates all three strictly and keeps the entire last-known-good snapshot on any
failure: never partial, never empties the registry, never opens the breaker.
Mirrors the signature subsystem (store + update_client.refresh + run_poll_loop +
last-known-good).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog
import yaml

from terminus.auth.registry import AgentEntry, AgentRegistry
from terminus.config.settings import get_settings
from terminus.observability.metrics import record_config_reload
from terminus.policy.policy_engine import PolicyConfig, PolicyEngine, SchemaWhitelist

_log = structlog.get_logger("terminus.governance")

_FILE_KEYS = ("policy", "whitelist", "agents")


@dataclass(frozen=True)
class GovernanceSnapshot:
    """Immutable snapshot of the active governance config."""

    engine: PolicyEngine
    registry: AgentRegistry
    version: str  # combined SHA-256 over the three files' raw bytes
    loaded_at: float  # epoch seconds of the load


def _hash_of(raw: dict[str, bytes]) -> str:
    """Combined SHA-256 over the three files' raw bytes in fixed order."""
    digest = hashlib.sha256()
    for key in _FILE_KEYS:
        digest.update(raw[key])
    return digest.hexdigest()


def _combined_hash(paths: dict[str, Path]) -> str:
    """SHA-256 over the three files' raw bytes in fixed order. Raises if any is missing."""
    return _hash_of({key: paths[key].read_bytes() for key in _FILE_KEYS})


def _parse_yaml_bytes(data: bytes) -> dict[str, Any]:
    """Parse YAML bytes into a dict (empty -> empty dict)."""
    return dict(yaml.safe_load(data) or {})


def build_policy_engine(
    policy_dict: dict[str, Any], whitelist_dict: dict[str, Any]
) -> PolicyEngine:
    """Validate the policy + whitelist dicts and construct a PolicyEngine."""
    dialect = get_settings().sql_dialect
    config = PolicyConfig.model_validate(policy_dict, context={"dialect": dialect})
    whitelist = SchemaWhitelist.model_validate(whitelist_dict, context={"dialect": dialect})

    # GAPS L3: max_queries_per_minute is parsed for forward compatibility but
    # NOT enforced anywhere; the only active rate limit is the global
    # TERMINUS_RATE_LIMIT_PER_MINUTE. Warn at snapshot build (boot and every
    # applied hot-reload) so the silent no-op is never mistaken for a control.
    # Resolved fresh (not the cached module-level `_log`) so structlog's
    # cache_logger_on_first_use never pins this call to whatever config
    # happened to be active the first time ANY governance event fired in the
    # process; that would make capture_logs()-based tests order-dependent.
    for rule in config.policies:
        if rule.limits is not None and rule.limits.max_queries_per_minute is not None:
            structlog.get_logger("terminus.governance").warning(
                "policy_limit_not_enforced",
                policy_id=rule.id,
                limit="max_queries_per_minute",
            )

    return PolicyEngine(
        config,
        whitelist=whitelist,
        enforce_injection=get_settings().enforce_injection_block,
    )


def build_agent_registry(agents_dict: dict[str, Any]) -> AgentRegistry:
    """Validate the agents dict and construct an AgentRegistry."""
    return AgentRegistry.model_validate(agents_dict)


def _governance_paths() -> dict[str, Path]:
    settings = get_settings()
    return {
        "policy": Path(settings.policy_path),
        "whitelist": Path(settings.schema_whitelist_path),
        "agents": Path(settings.agent_registry_path),
    }


def _load_snapshot(loaded_at: float) -> GovernanceSnapshot:
    """Read, validate, and bundle all three files. Strict: raises on any failure.

    Each file is read exactly once; the version hash and the parsed content come
    from the same bytes, so they can never describe different file contents.
    """
    paths = _governance_paths()
    raw = {key: paths[key].read_bytes() for key in _FILE_KEYS}  # one read each
    version = _hash_of(raw)
    engine = build_policy_engine(
        _parse_yaml_bytes(raw["policy"]), _parse_yaml_bytes(raw["whitelist"])
    )
    registry = build_agent_registry(_parse_yaml_bytes(raw["agents"]))
    return GovernanceSnapshot(
        engine=engine, registry=registry, version=version, loaded_at=loaded_at
    )


def _trust_changes(
    old: AgentRegistry, new: AgentRegistry
) -> list[tuple[str, str, str, AgentEntry]]:
    """Effective-trust deltas between two registry snapshots.

    Diffs EFFECTIVE trust (``AgentRegistry.trust_of``, which folds in
    ``status``), not the raw ``trust_level`` field: ``trust_of`` only honors a
    stored ``trust_level`` when ``status == "active"``, so a ``status`` flip
    alone (say, ``disabled`` -> ``active`` on a ``trust_level: observe``
    entry) changes what actually gets enforced even though ``trust_level``
    itself never moved. Diffing the raw field missed exactly that: a
    disabled-observe agent reactivated to active-observe silently went
    enforce -> observe with no signed event, and a brand-new disabled-observe
    entry (effective trust enforce, same as unregistered) spuriously emitted
    an unregistered -> observe promotion event it never earned.

    Emits (agent_id, previous, new, entry) for agents whose effective trust
    changed: present-in-both with a different ``trust_of`` result (this now
    also captures disabling an active observe agent as observe -> enforce, a
    tightening worth recording even though ``trust_level`` is untouched), or
    newly added with effective observe (previous "unregistered", since
    unregistered means enforce-by-default and observe is the posture that
    needs an audit trail; a newly added disabled-observe entry has effective
    trust enforce and so emits nothing). Removals still emit nothing: a
    removed agent is rejected by auth, which is stricter than enforce.
    """
    old_by_id = {a.id: a for a in old.agents}
    changes: list[tuple[str, str, str, AgentEntry]] = []
    for agent in new.agents:
        new_effective = new.trust_of(agent.id)
        prior = old_by_id.get(agent.id)
        if prior is None:
            if new_effective == "observe":
                changes.append((agent.id, "unregistered", new_effective, agent))
        else:
            old_effective = old.trust_of(agent.id)
            if old_effective != new_effective:
                changes.append((agent.id, old_effective, new_effective, agent))
    return changes


class GovernanceConfigManager:
    """Holds the active GovernanceSnapshot and reloads it from disk on demand.

    The initial snapshot is built at construction (so get_policy_engine /
    get_registry work on first access, like the prior lru_cache). A construction
    failure is fatal: there is no last-known-good yet, matching today's behavior.
    """

    def __init__(self) -> None:
        self._snapshot = _load_snapshot(time.time())

    @property
    def snapshot(self) -> GovernanceSnapshot:
        return self._snapshot

    def reload_now(self) -> str:
        """Reload if the files changed. Returns 'applied' | 'unchanged' | 'failed'.

        Off the request path. On any failure keeps the entire last-known-good
        snapshot and logs at ERROR; the breaker keeps enforcing the prior config.
        """
        try:
            version = _combined_hash(_governance_paths())
        except Exception as exc:
            _log.error(
                "config_reload_failed",
                error=exc.__class__.__name__,
                note="last-known-good retained",
            )
            record_config_reload("failed")
            return "failed"

        if version == self._snapshot.version:
            record_config_reload("unchanged")
            return "unchanged"

        try:
            new_snapshot = _load_snapshot(time.time())
        except Exception as exc:
            _log.error(
                "config_reload_failed",
                error=exc.__class__.__name__,
                note="last-known-good retained",
            )
            record_config_reload("failed")
            return "failed"

        old_registry = self._snapshot.registry
        self._snapshot = new_snapshot  # atomic single-attribute swap
        _log.info(
            "config_reloaded",
            version=new_snapshot.version[:12],
            agents=len(new_snapshot.registry.agents),
        )
        record_config_reload("applied")

        # Promotion/demotion audit trail: every trust change lands in the HMAC
        # chain. Emitted after the swap so the events describe applied config.
        try:
            from terminus.audit.audit_logger import AuditLogger

            audit = AuditLogger()
            for agent_id, prev, new, entry in _trust_changes(old_registry, new_snapshot.registry):
                audit.log_trust_change(
                    agent_id=agent_id,
                    previous_trust_level=prev,
                    new_trust_level=new,
                    governance_version=new_snapshot.version[:12],
                    trust_changed_by=entry.trust_changed_by,
                    trust_change_reason=entry.trust_change_reason,
                )
        except Exception as exc:  # reload already applied; never fail it for telemetry
            _log.error("trust_change_audit_failed", error=exc.__class__.__name__)

        return "applied"


@lru_cache(maxsize=1)
def get_governance_manager() -> GovernanceConfigManager:
    """Process singleton; builds the initial snapshot on first access."""
    return GovernanceConfigManager()


async def run_config_poll_loop(manager: GovernanceConfigManager, interval: int) -> None:
    """Reload every `interval` seconds until cancelled. Started only when interval > 0."""
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval)
        manager.reload_now()
