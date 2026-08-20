from __future__ import annotations

from pathlib import Path
from typing import Protocol, TypeVar

import yaml

from .models import DetectorRelease, Registry, ScannerRelease


class HasID(Protocol):
    id: str


T = TypeVar("T", bound=HasID)


class RegistryError(ValueError):
    pass


class RegistryService:
    def __init__(self, path: Path):
        self.path = path
        self.registry = self._load(path)
        self.validate_cross_references()

    @staticmethod
    def _load(path: Path) -> Registry:
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        return Registry.model_validate(data)

    @staticmethod
    def _unique(items: list[T], kind: str) -> dict[str, T]:
        result: dict[str, T] = {}
        for item in items:
            identifier = item.id
            if identifier in result:
                raise RegistryError(f"duplicate {kind} ID: {identifier}")
            result[identifier] = item
        return result

    def validate_cross_references(self) -> None:
        r = self.registry
        platforms = self._unique(r.platforms, "platform")
        products = self._unique(r.products, "product")
        runtimes = self._unique(r.runtime_profiles, "runtime profile")
        workers = self._unique(r.worker_profiles, "worker profile")
        releases = self._unique(r.scanner_releases, "scanner release")
        detectors = self._unique(r.detector_releases, "detector release")
        self._unique(r.definition_sets, "definition set")
        all_releases: list[ScannerRelease | DetectorRelease] = [
            *releases.values(),
            *detectors.values(),
        ]
        for release in all_releases:
            if release.product_id not in products:
                raise RegistryError(f"{release.id}: unknown product {release.product_id}")
            missing = set(release.platform_ids) - platforms.keys()
            if missing:
                raise RegistryError(f"{release.id}: unknown platforms {sorted(missing)}")
            if release.runtime_profile_id not in runtimes:
                raise RegistryError(f"{release.id}: unknown runtime {release.runtime_profile_id}")
            if release.worker_profile_id not in workers:
                raise RegistryError(f"{release.id}: unknown worker {release.worker_profile_id}")
        for definition in r.definition_sets:
            if definition.product_id not in products:
                raise RegistryError(f"{definition.id}: unknown product {definition.product_id}")
