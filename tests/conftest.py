from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def registry_path() -> Path:
    return Path("config/registry/registry.yaml")
