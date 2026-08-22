from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class PathSettings(BaseModel):
    state: Path
    staging: Path
    jobs: Path
    quarantine: Path
    scratch: Path
    raw_output: Path
    rules: Path
    registry: Path


class StorageSettings(BaseModel):
    sqlite_path: Path
    clean_bytes_retention_hours: int = Field(ge=0, default=0)
    minimum_free_gib: int = Field(ge=1, default=5)


class QuarantineSettings(BaseModel):
    enabled: bool = True
    content_addressed: bool = True
    immutable_after_admission: bool = True


class RuntimeSettings(BaseModel):
    worker_concurrency: int = Field(ge=1, le=64, default=2)
    default_timeout_seconds: int = Field(ge=1, default=300)
    memory_limit_mib: int = Field(ge=64, default=1024)
    maximum_file_bytes: int = Field(ge=1, default=1024 * 1024 * 1024)
    use_bubblewrap: bool = True
    default_file_detectors: list[str] = Field(
        default_factory=lambda: ["clamav", "yara", "yara-x", "loki", "maldet"]
    )
    strings_min_length: int = Field(ge=2, le=1024, default=4)
    strings_max_length: int = Field(ge=4, le=65536, default=4096)
    strings_max_count: int = Field(ge=1, le=100000, default=2000)
    strings_max_total_chars: int = Field(ge=64, le=10_000_000, default=200_000)
    strings_max_source_bytes: int = Field(ge=1024, default=16 * 1024 * 1024)
    metadata_max_fields: int = Field(ge=1, le=10000, default=256)
    metadata_max_value_length: int = Field(ge=32, le=1_000_000, default=4096)
    metadata_max_total_chars: int = Field(ge=128, le=10_000_000, default=200_000)
    max_recursion_depth: int = Field(ge=0, le=32, default=3)
    max_children_per_object: int = Field(ge=1, le=10000, default=100)
    max_total_children: int = Field(ge=1, le=100000, default=1000)
    max_single_child_bytes: int = Field(ge=1, default=64 * 1024 * 1024)
    max_total_extracted_bytes: int = Field(ge=1, default=512 * 1024 * 1024)
    max_expansion_ratio: float = Field(ge=1.0, le=1_000_000.0, default=100.0)
    max_member_name_bytes: int = Field(ge=1, le=65536, default=4096)
    max_path_depth: int = Field(ge=1, le=256, default=32)
    max_extraction_time_seconds: int = Field(ge=1, default=300)
    max_partitions_per_disk: int = Field(ge=1, le=256, default=32)
    max_materialized_partition_bytes: int = Field(ge=1, default=256 * 1024 * 1024)
    max_total_materialized_partition_bytes: int = Field(ge=1, default=512 * 1024 * 1024)
    max_executable_parser_bytes: int = Field(ge=1024, default=64 * 1024 * 1024)
    max_document_parser_bytes: int = Field(ge=1024, default=64 * 1024 * 1024)
    max_document_components: int = Field(ge=1, le=100000, default=10000)
    max_document_xml_depth: int = Field(ge=1, le=1024, default=64)
    max_rtf_group_depth: int = Field(ge=1, le=10000, default=256)
    max_structural_validation_bytes: int = Field(ge=1024, default=256 * 1024 * 1024)
    max_structural_validation_nodes: int = Field(ge=1, le=10_000_000, default=100_000)


class APISettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(ge=1, le=65535, default=8080)
    explicit_lan_exposure: bool = False

    @model_validator(mode="after")
    def require_explicit_lan_opt_in(self) -> APISettings:
        address = ip_address(self.host)
        if not address.is_loopback and not self.explicit_lan_exposure:
            raise ValueError("non-loopback API binding requires explicit_lan_exposure=true")
        return self


class WebSettings(BaseModel):
    enabled: bool = True


class LoggingSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    json_output: bool = Field(default=True, alias="json")


class PreservationSettings(BaseModel):
    external_manifests_enabled: bool = True
    bootstrap_import_enabled: bool = True


class RABSettings(BaseModel):
    enabled: bool = False
    endpoint: str | None = None
    export_directory: Path


class RABProtocolSettings(BaseModel):
    enabled: bool = False
    credential_file: Path
    profiles_file: Path
    upload_root: Path
    maximum_upload_bytes: int = Field(ge=1, default=1024 * 1024 * 1024)
    queue_capacity: int = Field(ge=1, le=10000, default=16)
    worker_concurrency: int = Field(ge=1, le=16, default=1)


class AppSettings(BaseModel):
    paths: PathSettings
    storage: StorageSettings
    quarantine: QuarantineSettings = Field(default_factory=QuarantineSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    api: APISettings = Field(default_factory=APISettings)
    web: WebSettings = Field(default_factory=WebSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    preservation: PreservationSettings = Field(default_factory=PreservationSettings)
    rab: RABSettings
    rab_protocol: RABProtocolSettings

    @classmethod
    def from_yaml(cls, path: Path) -> AppSettings:
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        if not isinstance(data, dict):
            raise ValueError("configuration root must be a mapping")
        return cls.model_validate(data)
