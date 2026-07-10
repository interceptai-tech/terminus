"""End-to-end: signatures emit for denies, never affect the response, never leak."""

from fastapi.testclient import TestClient

from terminus.main import app
from terminus.signature.emitter import get_signature_emitter
from terminus.signature.signature import Signature


class _Capture:
    def __init__(self) -> None:
        self.signatures: list[Signature] = []

    def emit(self, signature: Signature) -> None:
        self.signatures.append(signature)


def _client_with_capture() -> tuple[TestClient, _Capture]:
    cap = _Capture()
    app.dependency_overrides.pop(get_signature_emitter, None)
    app.dependency_overrides[get_signature_emitter] = lambda: cap
    return TestClient(app), cap


def teardown_function() -> None:
    app.dependency_overrides.pop(get_signature_emitter, None)


def test_deny_emits_signature_without_leaking() -> None:
    client, cap = _client_with_capture()
    resp = client.post(
        "/intercept",
        json={
            "sql": "SELECT password_hash FROM public.users WHERE password_hash = 'secretv'",
            "agent_id": "analytics_agent_42",
        },
    )
    assert resp.status_code == 403  # decision unaffected by signature work
    assert len(cap.signatures) == 1
    body = cap.signatures[0].model_dump_json()
    for token in ("password_hash", "secretv", "users"):
        assert token not in body


def test_benign_allow_does_not_emit() -> None:
    client, cap = _client_with_capture()
    resp = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users WHERE id = 1", "agent_id": "analytics_agent_42"},
    )
    assert resp.status_code == 200
    assert cap.signatures == []


def test_signature_gate_exception_does_not_break_request(monkeypatch) -> None:
    # If the gate itself raises, the request must still succeed (telemetry never 500s).
    import terminus.interceptor.router as router_mod

    def _boom(*_args, **_kwargs):
        raise RuntimeError("gate boom")

    monkeypatch.setattr(router_mod, "should_emit_signature", _boom)
    client = TestClient(app)
    resp = client.post(
        "/intercept",
        json={"sql": "SELECT id FROM public.users WHERE id = 1", "agent_id": "analytics_agent_42"},
    )
    assert resp.status_code == 200


def test_emitter_exception_does_not_break_request() -> None:
    # If the emitter raises, the decision must be unaffected.
    class _Boom:
        def emit(self, signature: Signature) -> None:
            raise RuntimeError("emit boom")

    app.dependency_overrides[get_signature_emitter] = lambda: _Boom()
    try:
        client = TestClient(app)
        resp = client.post(
            "/intercept",
            json={
                "sql": "SELECT password_hash FROM public.users WHERE id = 1",
                "agent_id": "analytics_agent_42",
            },
        )
        assert resp.status_code == 403
    finally:
        app.dependency_overrides.pop(get_signature_emitter, None)
