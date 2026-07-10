"""Static Dockerfile hardening assertions (GAPS M3, spec section 6).

These run in plain CI (no Docker daemon): they pin the hardening properties of
the Dockerfile TEXT so a regression is caught even where `docker build` cannot
run. The behavioral check is `make docker-smoke` (build + non-root + /health).
"""

from __future__ import annotations

import re
from pathlib import Path

_DOCKERFILE = (Path(__file__).parent.parent / "Dockerfile").read_text()


def _stages() -> list[str]:
    """Split the Dockerfile into per-stage chunks, each starting at its FROM."""
    parts = re.split(r"(?m)^FROM ", _DOCKERFILE)
    return ["FROM " + part for part in parts[1:]]


def test_dockerfile_is_multi_stage() -> None:
    assert len(_stages()) >= 2


def test_final_stage_runs_as_non_root() -> None:
    final = _stages()[-1]
    assert re.search(r"(?m)^USER terminus\s*$", final), "final stage must set USER terminus"


def test_build_toolchain_stays_in_builder() -> None:
    final = _stages()[-1]
    assert "build-essential" not in final
    assert "build-essential" in _stages()[0]


def test_runtime_does_not_install_dev_extra() -> None:
    assert ".[dev]" not in _DOCKERFILE and '"[dev]"' not in _DOCKERFILE


def test_runtime_keeps_wait_script_dependencies() -> None:
    final = _stages()[-1]
    assert "netcat-traditional" in final  # wait-for-redis.sh
    assert "curl" in final  # compose healthcheck


def test_cmd_does_not_use_uv_run() -> None:
    # `uv run` re-resolves into a venv and writes a cache, which breaks under a
    # non-root user; the baked image must exec python -m uvicorn directly.
    final = _stages()[-1]
    assert '"uv", "run"' not in final
    assert '"python", "-m", "uvicorn"' in final
