"""CI installs only declared dependencies (GAPS L2, spec section 2).

pyproject.toml is the single source of truth: the workflow must install the
dev extra and nothing ad-hoc. httpx2 (the client starlette.testclient needs)
must be declared there with a bounded pin, never as an unpinned ad-hoc
package on a CI install line.
"""

from __future__ import annotations

from pathlib import Path

_CI = (Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml").read_text()
_PYPROJECT = (Path(__file__).parent.parent / "pyproject.toml").read_text()


def test_ci_install_lines_are_declared_extras_only() -> None:
    install_lines = [line.strip() for line in _CI.splitlines() if "uv pip install" in line]
    assert install_lines, "expected at least one install line in ci.yml"
    for line in install_lines:
        assert line.endswith(
            'uv pip install --system -e ".[dev]"'
        ), f"ad-hoc package install in CI: {line}"


def test_httpx2_not_installed_ad_hoc_in_ci() -> None:
    # Belt-and-braces with the install-lines test above: httpx2 must never
    # ride along on a CI install line; it comes in via the declared dev extra.
    for line in _CI.splitlines():
        if "uv pip install" in line:
            assert "httpx2" not in line, f"ad-hoc httpx2 install in CI: {line.strip()}"


def test_httpx2_declared_and_pinned() -> None:
    declarations = [
        line.strip() for line in _PYPROJECT.splitlines() if line.strip().startswith('"httpx2')
    ]
    assert declarations, "httpx2 must be declared in pyproject.toml (dev extra)"
    for line in declarations:
        # A bare name would float to any future major; require an upper bound.
        assert "<" in line, f"httpx2 must carry an upper-bound pin, got: {line}"


def test_types_pyyaml_is_declared() -> None:
    assert "types-PyYAML" in _PYPROJECT


def test_httpx_declared_in_main_dependencies() -> None:
    import tomllib

    data = tomllib.loads(_PYPROJECT)
    deps = data["project"]["dependencies"]
    assert any(d.startswith("httpx") and "httpx2" not in d for d in deps), (
        "httpx must be a main dependency: it is imported at module scope by "
        "signature/update_client.py and outbound.py"
    )
