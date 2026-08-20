from pathlib import Path

import pytest
import yaml

from avbox.models import HistoricalMode, ScannerClass
from avbox.registry import RegistryError, RegistryService


def test_registry_loads_and_classes_exist(registry_path: Path) -> None:
    registry = RegistryService(registry_path).registry
    assert {product.scanner_class for product in registry.products} == set(ScannerClass)
    assert any(
        release.historical_mode is HistoricalMode.FINAL_HISTORICAL
        for release in registry.scanner_releases
    )


def _mutated_registry(tmp_path: Path, mutation: object) -> Path:
    data = yaml.safe_load(Path("config/registry/registry.yaml").read_text())
    mutation(data)
    path = tmp_path / "registry.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_duplicate_scanner_release_ids_fail(tmp_path: Path) -> None:
    path = _mutated_registry(
        tmp_path, lambda data: data["scanner_releases"].append(dict(data["scanner_releases"][0]))
    )
    with pytest.raises(RegistryError, match="duplicate scanner release ID"):
        RegistryService(path)


def test_invalid_platform_reference_fails(tmp_path: Path) -> None:
    def mutate(data: dict[str, object]) -> None:
        data["scanner_releases"][0]["platform_ids"] = ["nonexistent"]

    path = _mutated_registry(tmp_path, mutate)
    with pytest.raises(RegistryError, match="unknown platforms"):
        RegistryService(path)
