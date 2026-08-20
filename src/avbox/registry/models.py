from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field, model_validator

from avbox.models import Capability, DependencyMode, HistoricalMode, Rights
from avbox.models.common import ScannerClass


class Platform(BaseModel):
    id: str
    label: str
    family: str
    historical: bool


class ScannerProduct(BaseModel):
    id: str
    vendor: str
    product: str
    scanner_class: ScannerClass
    notes: str | None = None
    license: str | None = None


class ScannerRelease(BaseModel):
    id: str
    product_id: str
    product_version: str | None = None
    engine_version: str | None = None
    platform_ids: list[str]
    runtime_profile_id: str
    worker_profile_id: str
    historical_mode: HistoricalMode | None = None
    qualification_status: str
    capabilities: set[Capability] = Field(default_factory=set)
    dependency_mode: DependencyMode
    offline_definitions_supported: bool | None = None
    definition_snapshot_supported: bool | None = None
    rights: Rights = Field(default_factory=Rights)
    installation_source: str | None = None
    installation_method: str | None = None
    update_mechanism: str | None = None

    @model_validator(mode="after")
    def historical_mode_requires_historical_qualification(self) -> ScannerRelease:
        if (
            self.historical_mode
            and "incomplete" not in self.qualification_status
            and "qualified" not in self.qualification_status
        ):
            raise ValueError("historical mode requires explicit qualification status")
        return self


class DetectorRelease(BaseModel):
    id: str
    product_id: str
    product_version: str | None = None
    platform_ids: list[str]
    runtime_profile_id: str
    worker_profile_id: str
    capabilities: set[Capability]
    dependency_mode: DependencyMode
    qualification_status: str
    installation_source: str | None = None
    installation_method: str | None = None
    update_mechanism: str | None = None


class DefinitionSet(BaseModel):
    id: str
    product_id: str
    definition_version: str | None = None
    definition_date: date | None = None
    compatible_engine_versions: list[str] = Field(default_factory=list)
    compatibility_status: str


class RuntimeProfile(BaseModel):
    id: str
    mechanism: str
    platform_id: str
    network_policy: str = "none"


class WorkerProfile(BaseModel):
    id: str
    adapter: str
    isolation: str


class Registry(BaseModel):
    schema_version: int = 1
    platforms: list[Platform]
    products: list[ScannerProduct]
    scanner_releases: list[ScannerRelease] = Field(default_factory=list)
    detector_releases: list[DetectorRelease] = Field(default_factory=list)
    definition_sets: list[DefinitionSet] = Field(default_factory=list)
    runtime_profiles: list[RuntimeProfile]
    worker_profiles: list[WorkerProfile]
