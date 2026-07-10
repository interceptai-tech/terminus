"""Floor-and-tighten signature matcher.

Local policy is the floor and is never downgraded. An enforce-mode match (with
the global enforce posture on) escalates a local allow to a deny; an observe-mode
match, or any match while enforce is off, only reports (the caller logs/annotates).
"""

from __future__ import annotations

from dataclasses import dataclass

from terminus.policy.policy_engine import PolicyDecision
from terminus.signature.records import SignatureRecord
from terminus.signature.store import SignatureStore


@dataclass
class MatchResult:
    matched: bool
    record: SignatureRecord | None
    decision: PolicyDecision
    enforced: bool


def evaluate_match(
    fingerprint: str,
    local_decision: PolicyDecision,
    store: SignatureStore,
    *,
    enforce_enabled: bool,
) -> MatchResult:
    record = store.lookup(fingerprint)
    if record is None:
        return MatchResult(matched=False, record=None, decision=local_decision, enforced=False)

    should_enforce = enforce_enabled and record.mode == "enforce"
    if should_enforce and local_decision.action == "allow":
        escalated = PolicyDecision(
            action="deny",
            policy_id="signature_match",
            reason=(
                f"Matched Terminus threat-intelligence signature {record.signature_id} "
                f"(severity {record.severity})."
            ),
            reason_code="signature_match",
        )
        return MatchResult(matched=True, record=record, decision=escalated, enforced=True)

    # observe, enforce-posture-off, or an already-denied query: never change it
    return MatchResult(matched=True, record=record, decision=local_decision, enforced=False)
