from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from .analysis import (
    AnalyzerResult,
    Assessment,
    DerivedObject,
    ExtractionBudget,
    ExtractionUsage,
    Finding,
    ObjectRelationship,
    Observation,
    PreservationContext,
    StructuralValidation,
)
from .common import Verdict
from .jobs import JobStatus

PROTOCOL_VERSION = "1"


class ErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    FORBIDDEN = "FORBIDDEN"
    OBJECT_HASH_MISMATCH = "OBJECT_HASH_MISMATCH"
    OBJECT_TOO_LARGE = "OBJECT_TOO_LARGE"
    UNSUPPORTED_PROFILE = "UNSUPPORTED_PROFILE"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    QUEUE_FULL = "QUEUE_FULL"
    ANALYZER_UNAVAILABLE = "ANALYZER_UNAVAILABLE"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    STORAGE_UNAVAILABLE = "STORAGE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    NOT_FOUND = "NOT_FOUND"


class ProtocolError(BaseModel):
    protocol_version: Literal["1"] = "1"
    code: ErrorCode
    detail: str
    request_id: str | None = None


class ObjectIdentity(BaseModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    blake3: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    sha1: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    md5: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    size: int = Field(ge=0)
    filename: str | None = None
    media_type: str | None = None


class AnalysisProfile(BaseModel):
    id: str
    version: int
    analyzers: list[str]
    capabilities: list[str]
    enabled: bool = True

    @property
    def qualified_id(self) -> str:
        return f"{self.id}@{self.version}"


class AnalysisJobAccepted(BaseModel):
    protocol_version: Literal["1"] = "1"
    job_id: UUID
    object_id: str
    object_sha256: str
    profile: str
    state: JobStatus
    created_at: datetime
    duplicate: bool = False
    links: dict[str, str]


class AnalysisJobStatus(BaseModel):
    protocol_version: Literal["1"] = "1"
    job_id: UUID
    object_sha256: str
    profile: str
    state: JobStatus
    created_at: datetime
    updated_at: datetime
    client_request_id: str


class AnalysisResultEnvelope(BaseModel):
    protocol_version: Literal["1"] = "1"
    job_id: UUID
    object: ObjectIdentity
    profile: str
    state: JobStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    analyzers: list[AnalyzerResult] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    assessments: list[Assessment] = Field(default_factory=list)
    verdict: Verdict | None = None
    preservation_context: PreservationContext = Field(default_factory=PreservationContext)
    structural_validation: list[StructuralValidation] = Field(default_factory=list)
    relationships: list[ObjectRelationship] = Field(default_factory=list)
    derived_objects: list[DerivedObject] = Field(default_factory=list)
    completeness: str = "COMPLETE"
    extraction_budget: ExtractionBudget | None = None
    extraction_usage: ExtractionUsage | None = None
    errors: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
