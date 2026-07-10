"""Shared test fixtures."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# The test suite (and the dogfood PoV harness) run as `development` so the
# production secret guard (assert_production_secrets) does not refuse to boot on
# the shipped example defaults. Set before any terminus import so the cached
# settings pick it up. Real deployments must set TERMINUS_ENVIRONMENT + secrets.
os.environ.setdefault("TERMINUS_ENVIRONMENT", "development")

# Ensure pov/ package root is discoverable for tests before pytest collection
_project_root = str(Path(__file__).parent.parent.absolute())
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


@pytest.fixture
def reset_auth_caches():
    """Reset cached settings + governance manager so per-test env vars take effect.

    get_settings() and get_governance_manager() cache on first call; tests that
    set TERMINUS_* env vars must clear those caches before issuing a request. The
    fixture yields a callable so a test can re-clear after setting env vars,
    and clears again on teardown to avoid leaking state into other tests.
    """
    import terminus.config.settings as settings_mod
    from terminus.config.governance import get_governance_manager

    def _reset() -> None:
        settings_mod._settings = None
        get_governance_manager.cache_clear()

    _reset()
    yield _reset
    _reset()
