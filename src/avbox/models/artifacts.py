from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import RightsStatus


class Hashes(BaseModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    blake3: str = Field(pattern=r"^[0-9a-f]{64}$")
    sha1: str = Field(pattern=r"^[0-9a-f]{40}$")
    md5: str = Field(pattern=r"^[0-9a-f]{32}$")


class Rights(BaseModel):
    redistribution_rights: RightsStatus = RightsStatus.UNKNOWN
    acquisition_basis: str | None = None
    source_provenance: str | None = None


class InputArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)
    hashes: Hashes
    byte_size: int = Field(ge=0)
    filename: str
    media_type: str
    source: str
    submitted_at: datetime
    rights: Rights = Field(default_factory=Rights)

    @property
    def identity(self) -> str:
        return self.hashes.sha256


class RepairRecord(BaseModel):
    source_artifact_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    working_copy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scanner_id: str
    scanner_version: str | None = None
    definition_version: str | None = None
    repair_action: str
    repaired_artifact_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scanner_output_ref: str
    timestamp: datetime

    @model_validator(mode="after")
    def original_must_not_be_working_copy(self) -> RepairRecord:
        if self.source_artifact_hash == self.working_copy_hash:
            raise ValueError("repair working copy must not be the immutable original")
        if self.source_artifact_hash == self.repaired_artifact_hash:
            raise ValueError("repaired candidate must not target the immutable original")
        return self
