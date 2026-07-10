"""End-to-end: enforce-mode match escalates allow->deny; never breaks the request."""

import pytest
from fastapi.testclient import TestClient

import terminus.config.settings as settings_mod
from terminus.main import app
from terminus.parser.sql_parser import parse_sql
from terminus.policy.policy_engine import PolicyEngine
from terminus.signature.facts import RoleResolver
from terminus.signature.records import SignatureRecord
from terminus.signature.signature import fingerprint_for
from terminus.signature.store import get_signature_store

_ALLOWED_SQL = {"sql": "SELECT id FROM public.users WHERE id = 1", "agent_id": "analytics_agent_42"}


def _fingerprint_of(sql: str) -> str:
    engine = PolicyEngine.from_default_policy()
    parsed = parse_sql(sql, collect_signature_facts=True)
    fp, _f, _t = fingerprint_for(parsed, RoleResolver(engine.whitelist))
    return fp


@pytest.fixture
def matching_on(monkeypatch):
    monkeypatch.setenv("TERMINUS_SIGNATURE_MATCHING_ENABLED", "true")
    monkeypatch.setenv("TERMINUS_SIGNATURE_ENFORCE_ENABLED", "true")
    settings_mod._settings = None
    get_signature_store().swap([])  # start empty
    yield
    settings_mod._settings = None
    get_signature_store().swap([])


def test_enforce_match_escalates_allow_to_deny(matching_on) -> None:
    fp = _fingerprint_of(_ALLOWED_SQL["sql"])
    get_signature_store().swap(
        [
            SignatureRecord(
                signature_id="sig-1",
                query_fingerprint=fp,
                fingerprint_version="1",
                severity="high",
                mode="enforce",
            )
        ]
    )
    resp = TestClient(app).post("/intercept", json=_ALLOWED_SQL)
    assert resp.status_code == 403
    assert resp.json()["policy_id"] == "signature_match"


def test_no_match_still_allows(matching_on) -> None:
    resp = TestClient(app).post("/intercept", json=_ALLOWED_SQL)
    assert resp.status_code == 200  # empty store: nothing matches


def test_observe_match_does_not_change_decision(matching_on) -> None:
    fp = _fingerprint_of(_ALLOWED_SQL["sql"])
    get_signature_store().swap(
        [
            SignatureRecord(
                signature_id="sig-obs",
                query_fingerprint=fp,
                fingerprint_version="1",
                severity="low",
                mode="observe",
            )
        ]
    )
    resp = TestClient(app).post("/intercept", json=_ALLOWED_SQL)
    # observe must not escalate, even with enforce_enabled=true posture on
    assert resp.status_code == 200
