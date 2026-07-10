"""Functional run + self-correction, driven through the real app via TestClient."""

from __future__ import annotations

from fastapi.testclient import TestClient

from pov.functional import run_functional, self_correction_breakdown
from pov.models import CorpusEntry
from terminus.main import app

_ENTRIES = [
    CorpusEntry(
        id="allow_read",
        sql="SELECT id FROM public.users WHERE id = 1",
        category="benign_read",
        expected_decision="allow",
    ),
    CorpusEntry(
        id="deny_drop",
        sql="DROP TABLE public.users",
        category="destructive_ddl",
        expected_decision="deny",
        self_correctable=False,
    ),
    CorpusEntry(
        id="col_star",
        sql="SELECT * FROM public.users",
        category="column_violation",
        expected_decision="deny",
        self_correctable=True,
    ),
    CorpusEntry(
        id="update_no_where",
        sql="UPDATE public.users SET name = 'x'",
        category="dangerous_dml",
        expected_decision="deny",
        self_correctable=True,
    ),
]


def test_decisions_match_expected() -> None:
    with TestClient(app) as client:
        outcomes = run_functional(client, _ENTRIES)
    by_id = {o.id: o for o in outcomes}
    assert by_id["allow_read"].actual_decision == "allow"
    assert by_id["deny_drop"].actual_decision == "deny"
    assert all(o.decision_correct for o in outcomes)


def test_self_correction_via_suggested_sql_and_rule() -> None:
    with TestClient(app) as client:
        outcomes = run_functional(client, _ENTRIES)
    by_id = {o.id: o for o in outcomes}
    assert by_id["col_star"].corrected is True
    assert by_id["col_star"].used_suggested_sql is True
    assert by_id["update_no_where"].corrected is True  # rule-based WHERE
    assert by_id["update_no_where"].used_suggested_sql is False  # pin rule-based path
    breakdown = self_correction_breakdown(outcomes)
    assert breakdown.self_correctable == 2
    assert breakdown.corrected == 2
    assert breakdown.escalated_to_human == 1  # the DROP


def test_fail_safe_no_decision_key() -> None:
    """Prove fail-safe: a response lacking a decision key (error, 429, 422)
    is treated as a deny: the safe default for a circuit-breaker validation tool."""

    class _NoDecisionResp:
        def json(self) -> dict[str, str]:
            return {"detail": "rate limited"}

    class _NoDecisionClient:
        def post(self, url: str, *, json: dict) -> _NoDecisionResp:
            return _NoDecisionResp()

    # Single entry that would normally be allowed, but our stub client always
    # returns a no-decision response (like a 429 or 422).
    entries = [
        CorpusEntry(
            id="rate_limited",
            sql="SELECT id FROM public.users WHERE id = 1",
            category="benign_read",
            expected_decision="allow",
        )
    ]

    # The run should NOT raise. The outcome should record actual_decision as "deny"
    # (the safe fail-safe default).
    client = _NoDecisionClient()  # type: ignore
    outcomes = run_functional(client, entries)

    assert len(outcomes) == 1
    assert outcomes[0].actual_decision == "deny"
    assert outcomes[0].decision_correct is False  # expected allow, got deny
