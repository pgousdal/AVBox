from pathlib import Path

import pytest

from avbox.application import PolicyService
from avbox.models import ScanPolicy
from avbox.preservation import PreservationService


def test_m0_policy_rejects_repair() -> None:
    PolicyService.require_read_only(ScanPolicy.READ_ONLY)
    with pytest.raises(PermissionError):
        PolicyService.require_read_only(ScanPolicy.REPAIR_COPY)


def test_external_manifest_boundary() -> None:
    manifest = PreservationService.load_external_manifest(
        Path("examples/external-preservation-manifest.json")
    )
    assert manifest.authority == "example-external-preservation-system"
    assert manifest.artifacts[0].rights.redistribution_rights == "unknown"
