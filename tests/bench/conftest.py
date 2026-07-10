"""Conftest for bench tests - ensures bench module is importable."""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path so bench can be imported
_project_root = str(Path(__file__).parent.parent.parent.absolute())
if _project_root in sys.path:
    sys.path.remove(_project_root)
sys.path.insert(0, _project_root)
