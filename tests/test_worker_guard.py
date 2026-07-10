"""Multi-worker boot guard (GAPS H1, spec section 3).

Positive evidence only: unknown boots. The parser is pure; the /proc reader is
injected so no test needs a real process tree.
"""

from __future__ import annotations

import pytest

from terminus.config.settings import TerminusSettings
from terminus.config.worker_guard import (
    assert_single_worker,
    detect_worker_count,
    parse_worker_count_from_cmdline,
)


@pytest.mark.parametrize(
    ("cmdline", "expected"),
    [
        ("uvicorn terminus.main:app --workers 4", 4),
        ("uvicorn terminus.main:app --workers=4", 4),
        ("gunicorn -w 2 terminus.main:app", 2),
        ("gunicorn -w4 terminus.main:app", 4),
        ("gunicorn --workers 3 -k uvicorn.workers.UvicornWorker app", 3),
        ("uvicorn terminus.main:app -w 1", 1),
        ("uvicorn terminus.main:app --reload", None),
        ("uvicorn terminus.main:app", None),
        ("", None),
        ("--workers banana", None),
        ("--workers 0", None),
    ],
)
def test_parse_worker_count_from_cmdline(cmdline: str, expected: int | None) -> None:
    assert parse_worker_count_from_cmdline(cmdline) == expected


def _settings(**kwargs: object) -> TerminusSettings:
    return TerminusSettings(**kwargs)  # type: ignore[arg-type]


def test_detection_precedence_settings_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB_CONCURRENCY", "8")
    s = _settings(environment="development", worker_count=1)
    assert detect_worker_count(s, read_parent_cmdline=lambda: "--workers 4") == (
        1,
        "TERMINUS_WORKER_COUNT",
    )


def test_detection_web_concurrency_beats_cmdline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    s = _settings(environment="development")
    assert detect_worker_count(s, read_parent_cmdline=lambda: "--workers 4") == (
        2,
        "WEB_CONCURRENCY",
    )


def test_detection_falls_back_to_parent_cmdline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    s = _settings(environment="development")
    assert detect_worker_count(s, read_parent_cmdline=lambda: "uvicorn --workers 4") == (
        4,
        "parent_cmdline",
    )


def test_detection_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    s = _settings(environment="production")
    assert detect_worker_count(s, read_parent_cmdline=lambda: None) == (None, "unknown")


def test_garbage_web_concurrency_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEB_CONCURRENCY", "not-a-number")
    s = _settings(environment="production")
    assert detect_worker_count(s, read_parent_cmdline=lambda: None) == (None, "unknown")


@pytest.mark.parametrize("env", ["staging", "production"])
def test_hardened_multi_worker_refuses_boot(env: str) -> None:
    s = _settings(environment=env, worker_count=2)
    with pytest.raises(RuntimeError, match="refusing to start"):
        assert_single_worker(s, read_parent_cmdline=lambda: None)


def test_development_multi_worker_warns_and_boots() -> None:
    s = _settings(environment="development", worker_count=2)
    assert_single_worker(s, read_parent_cmdline=lambda: None)  # must not raise


def test_escape_hatch_boots_in_production() -> None:
    s = _settings(environment="production", worker_count=2, allow_unsafe_multi_worker=True)
    assert_single_worker(s, read_parent_cmdline=lambda: None)  # must not raise


def test_unknown_count_boots_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    s = _settings(environment="production")
    assert_single_worker(s, read_parent_cmdline=lambda: None)  # must not raise


def test_single_worker_boots_everywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    for env in ("development", "staging", "production"):
        s = _settings(environment=env, worker_count=1)
        assert_single_worker(s, read_parent_cmdline=lambda: None)


def test_lifespan_wires_the_guard(monkeypatch: pytest.MonkeyPatch, reset_auth_caches) -> None:
    """End to end: production + TERMINUS_WORKER_COUNT=2 + real secrets fails at startup."""
    from fastapi.testclient import TestClient

    from terminus.main import create_app

    monkeypatch.setenv("TERMINUS_ENVIRONMENT", "production")
    monkeypatch.setenv("TERMINUS_WORKER_COUNT", "2")
    monkeypatch.setenv("TERMINUS_JWT_SECRET", "x" * 48)
    monkeypatch.setenv("TERMINUS_AUDIT_HMAC_KEY", "y" * 48)
    reset_auth_caches()
    with pytest.raises(RuntimeError, match="refusing to start"):  # noqa: SIM117
        with TestClient(create_app()):
            pass
