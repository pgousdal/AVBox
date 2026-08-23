from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from .artifacts import Rights


class CorrelationState(StrEnum):
    NOT_REQUESTED = "NOT_REQUESTED"
    UNAVAILABLE = "UNAVAILABLE"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"


class ExactLookupState(StrEnum):
    EXACT_MATCH = "EXACT_MATCH"
    NO_EXACT_MATCH = "NO_EXACT_MATCH"
    RAB_UNAVAILABLE = "RAB_UNAVAILABLE"
    ERROR = "ERROR"


class CorrelationErrorCode(StrEnum):
    RAB_UNAVAILABLE = "RAB_UNAVAILABLE"
    RAB_TIMEOUT = "RAB_TIMEOUT"
    RAB_AUTH_FAILED = "RAB_AUTH_FAILED"
    RAB_PROTOCOL_ERROR = "RAB_PROTOCOL_ERROR"
    RAB_RESPONSE_TOO_LARGE = "RAB_RESPONSE_TOO_LARGE"
    RAB_IDENTITY_CONFLICT = "RAB_IDENTITY_CONFLICT"


class ProvenanceRecord(BaseModel):
    source_id: str | None = None
    source_label: str | None = None
    collection: str | None = None
    acquired_at: datetime | None = None
    summary: str | None = None
    authority: str = "RAB"


class KnownOccurrence(BaseModel):
    parent_rab_object_id: str
    relationship: str
    logical_path: str | None = None
    parent_label: str | None = None
    authority: str = "RAB"


class StructuralHistoryRecord(BaseModel):
    state: str
    observed_at: datetime | None = None
    validator: str | None = None
    summary: str | None = None
    authority: str = "RAB"


class RABObjectContext(BaseModel):
    rab_object_id: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    known_filenames: list[str] = Field(default_factory=list)
    format_classification: str | None = None
    source_collections: list[str] = Field(default_factory=list)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    rights: Rights | None = None
    physical_original_owned: bool | None = None
    preservation_status: str | None = None
    structural_validation_history: list[StructuralHistoryRecord] = Field(default_factory=list)
    metadata_urls: list[str] = Field(default_factory=list)
    authority: str = "RAB"


class ExactMatch(BaseModel):
    rab_object_id: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)
    matched_hashes: list[str] = Field(default_factory=lambda: ["sha256"])
    context: RABObjectContext | None = None
    authority: str = "RAB"


class ExactCorrelation(BaseModel):
    state: ExactLookupState = ExactLookupState.RAB_UNAVAILABLE
    matches: list[ExactMatch] = Field(default_factory=list)
    completeness: CorrelationState = CorrelationState.UNAVAILABLE


class SimilarityCandidate(BaseModel):
    algorithm: str
    query_fingerprint: str
    candidate_fingerprint: str
    score: int = Field(ge=0, le=100)
    rab_object_id: str
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment: str = "candidate"
    authority: str = "RAB"


class SimilarityCorrelation(BaseModel):
    algorithm: str = "ssdeep"
    state: CorrelationState = CorrelationState.NOT_REQUESTED
    candidates: list[SimilarityCandidate] = Field(default_factory=list)


class CorrelationResult(BaseModel):
    protocol_version: str = "1"
    provider_id: str
    provider_version: str
    state: CorrelationState
    exact: ExactCorrelation
    similarity: SimilarityCorrelation = Field(default_factory=SimilarityCorrelation)
    known_occurrences: list[KnownOccurrence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[CorrelationErrorCode] = Field(default_factory=list)
    skipped_reason: str | None = None
    fetched_at: datetime | None = None
    from_cache: bool = False
