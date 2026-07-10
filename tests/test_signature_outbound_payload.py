"""OutboundPayload mapping from a Signature."""

from terminus.signature.outbound import _to_payload
from terminus.signature.signature import Signature, SignatureStructure


def _signature(**over) -> Signature:
    base = {
        "query_fingerprint": "a3f1c9",
        "operation": "SELECT",
        "decision": "deny",
        "reason_code": "column_whitelist",
        "risk_score": 0.72,
        "risk_reasons": ["wildcard_select"],
        "technique": "aggregate_oracle_probe",
        "structure": SignatureStructure(
            has_where=True,
            has_aggregate=True,
            aggregate_only=True,
            has_subquery=False,
            has_union=False,
            join_count=0,
            wildcard="none",
            predicate_ops=["LIKE"],
            projection_roles=["aggregate"],
            predicate_roles=["restricted"],
            table_roles=["restricted"],
        ),
        "security_flags": [],
        "smuggling_markers": [],
        "emitted_at": "2026-06-22T14:37:11Z",
    }
    base.update(over)
    return Signature(**base)


def test_payload_maps_fields() -> None:
    p = _to_payload(_signature())
    assert p.payload_version == "1"
    assert p.query_fingerprint == "a3f1c9"
    assert p.fingerprint_version == "1"  # = Signature.schema_version default
    assert p.operation == "SELECT"
    assert p.technique == "aggregate_oracle_probe"
    assert p.local_decision == "deny"
    assert p.local_risk_score == 0.72
    assert p.structure.predicate_ops == ["LIKE"]


def test_observed_at_truncated_to_hour() -> None:
    p = _to_payload(_signature())
    # observed_at is "now" truncated to the hour: minutes/seconds are zero.
    assert p.observed_at.endswith(":00:00+00:00") or p.observed_at.endswith(":00:00")
