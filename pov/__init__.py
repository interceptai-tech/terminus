"""Terminus PoV validation harness package.

The harness boots the real app (via TestClient) against the shipped example
config. Default it to `development` so the production secret guard
(assert_production_secrets) does not refuse to boot on the example default
secrets. Set here, before `pov.harness` imports `terminus.main`, so the cached
settings pick it up. An explicit TERMINUS_ENVIRONMENT in the environment wins.
"""

from __future__ import annotations

import os

os.environ.setdefault("TERMINUS_ENVIRONMENT", "development")
