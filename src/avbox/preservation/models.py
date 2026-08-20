from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from avbox.models import Hashes, Rights


class ExternalArtifact(BaseModel):
    original_filename: str
    hashes: Hashes
    byte_size: int = Field(ge=0)
    source_urls: list[str] = Field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    product_version: str | None = None
    engine_version: str | None = None
    definition_version: str | None = None
    definition_date: datetime | None = None
    compatibility: dict[str, object] = Field(default_factory=dict)
    relationships: list[dict[str, object]] = Field(default_factory=list)
    provenance_events: list[dict[str, object]] = Field(default_factory=list)
    rights: Rights = Field(default_factory=Rights)


class ExternalPreservationManifest(BaseModel):
    schema_version: int
    authority: str
    generated_at: datetime
    artifacts: list[ExternalArtifact]
    failed_sources: list[dict[str, object]] = Field(default_factory=list)


class RABResourceRequest(BaseModel):
    request_id: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_scanners: list[str]


class RABResultEnvelope(BaseModel):
    request_id: str
    job_id: str
    artifact_sha256: str
    result_document: dict[str, object]
