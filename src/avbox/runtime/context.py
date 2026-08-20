from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from avbox.application import JobService
from avbox.config import AppSettings
from avbox.registry import RegistryService


@dataclass
class Context:
    settings: AppSettings
    registry: RegistryService
    jobs: JobService


def build_context(config_path: Path | None = None) -> Context:
    selected = config_path or Path(os.environ.get("AVBOX_CONFIG", "config/avbox.yaml"))
    settings = AppSettings.from_yaml(selected)
    registry = RegistryService(settings.paths.registry)
    return Context(
        settings=settings, registry=registry, jobs=JobService(settings.storage.sqlite_path)
    )
