"""Docs-disable wiring (GAPS M5, spec section 7).

create_app() binds disable_docs at construction, so every test builds a FRESH
app after setting env + resetting the settings cache (module-level `app` in
terminus.main is import-time-bound and must not be used here).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _fresh_app(monkeypatch: pytest.MonkeyPatch, reset, env: str, **extra_env: str):
    from terminus.main import create_app

    monkeypatch.setenv("TERMINUS_ENVIRONMENT", env)
    for key, value in extra_env.items():
        monkeypatch.setenv(key, value)
    reset()
    return create_app()


def test_production_default_disables_docs_surface(
    monkeypatch: pytest.MonkeyPatch, reset_auth_caches
) -> None:
    app = _fresh_app(monkeypatch, reset_auth_caches, "production")
    client = TestClient(app)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_operational_endpoints_survive_docs_disable(
    monkeypatch: pytest.MonkeyPatch, reset_auth_caches
) -> None:
    app = _fresh_app(monkeypatch, reset_auth_caches, "production")
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/metrics").status_code == 200
    body = client.get("/").json()
    assert "docs" not in body
    assert body["health"] == "/health"


def test_development_default_serves_docs(
    monkeypatch: pytest.MonkeyPatch, reset_auth_caches
) -> None:
    app = _fresh_app(monkeypatch, reset_auth_caches, "development")
    client = TestClient(app)
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/").json()["docs"] == "/docs"


def test_explicit_override_reenables_docs_in_production(
    monkeypatch: pytest.MonkeyPatch, reset_auth_caches
) -> None:
    app = _fresh_app(monkeypatch, reset_auth_caches, "production", TERMINUS_DISABLE_DOCS="false")
    client = TestClient(app)
    assert client.get("/docs").status_code == 200
