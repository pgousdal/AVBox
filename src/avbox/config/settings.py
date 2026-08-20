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

    @classmethod
    def from_yaml(cls, path: Path) -> AppSettings:
        with path.open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        if not isinstance(data, dict):
            raise ValueError("configuration root must be a mapping")
        return cls.model_validate(data)
