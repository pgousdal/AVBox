from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from .common import QualificationState, ScannerClass, Verdict
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


class Observation(BaseModel):
    observation_type: str
    value: Any
    analyzer_id: str
    evidence_refs: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_type: str
    analyzer_id: str
    native_name: str | None = None
    normalized_verdict: Verdict | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class Assessment(BaseModel):
    assessment_type: str
    analyzer_id: str
    statement: str
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_refs: list[str] = Field(default_factory=list)


class PreservationContext(BaseModel):
    rab_correlation: Literal["NOT_AVAILABLE"] = "NOT_AVAILABLE"
    recommendation: str | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)


class ObjectRelationship(BaseModel):
    relationship: Literal[
        "CONTAINS",
        "EMBEDS",
        "EXTRACTED_FROM",
        "DERIVED_FROM",
        "REPAIRED_FROM",
        "SIMILAR_TO",
        "DUPLICATE_OF",
    ]
    source_sha256: str
    target_sha256: str
    evidence_refs: list[str] = Field(default_factory=list)


class RawOutputDescriptor(BaseModel):
    raw_output_id: str
    sha256: str | None = None
    size: int | None = None
    media_type: Literal["text/plain"] = "text/plain"


class AnalyzerResult(BaseModel):
    analyzer_id: str
    analyzer_class: ScannerClass | str
    product: str
    product_version: str | None = None
    engine_version: str | None = None
    definition_state: dict[str, str | int | None] = Field(default_factory=dict)
    qualification_state: QualificationState | None = None
    started_at: datetime | None = None
    completed_at: datetime
    duration_seconds: float | None = None
    execution_profile: str
    native_status: str
    native_exit_code: int | None = None
    normalized_verdict: Verdict | None = None
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    assessments: list[Assessment] = Field(default_factory=list)
    raw_output: RawOutputDescriptor | None = None
    errors: list[str] = Field(default_factory=list)


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
    relationships: list[ObjectRelationship] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
