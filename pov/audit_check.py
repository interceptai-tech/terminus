"""Audit completeness: one complete, chain-verified event per intercepted request."""

from __future__ import annotations

import json
from collections.abc import Sequence

from pov.models import AuditCompleteness
from terminus.audit.verify import verify_audit_chain

_AUDIT_EVENT_NAME = "terminus_intercept_decision"


def check_audit_completeness(
    log_lines: Sequence[str], sent_request_ids: Sequence[str], hmac_key: str
) -> AuditCompleteness:
    """Confirm every sent request produced one audit event and the chain verifies.

    Chain verification reuses terminus.audit.verify.verify_audit_chain (the same
    helper an auditor or SIEM would use), anchored at genesis since the harness
    starts a fresh Terminus process per run.
    """
    audited_ids: set[str] = set()
    for line in log_lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("event") == _AUDIT_EVENT_NAME:
            rid = event.get("request_id")
            if isinstance(rid, str):
                audited_ids.add(rid)

    chain = verify_audit_chain(log_lines, hmac_key, require_genesis=True)
    return AuditCompleteness(
        total_requests=len(set(sent_request_ids)),
        audited=len(audited_ids & set(sent_request_ids)),
        verified_count=chain.verified_count,
        chain_ok=chain.ok and chain.verified_count > 0,
        failures=[f"{f.reason}@{f.index}" for f in chain.failures],
    )
