from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from .common import Confidence, QualificationState, ScannerClass, StructuralState, Verdict
from .correlation import CorrelationResult


class Observation(BaseModel):
    observation_type: str
    value: Any
    analyzer_id: str
    evidence_refs: list[str] = Field(default_factory=list)
    source: str | None = None
    observed_at: datetime | None = None
    confidence: Literal["exact"] | None = None


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
    confidence: Confidence = Confidence.UNKNOWN
    evidence_refs: list[str] = Field(default_factory=list)


class PreservationContext(BaseModel):
    rab_correlation: Literal["NOT_AVAILABLE", "AVAILABLE"] = "NOT_AVAILABLE"
    correlation: CorrelationResult | None = None
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
        "MEMBER_OF",
        "DECOMPRESSED_FROM",
        "FILESYSTEM_ENTRY_OF",
        "PARTITION_OF",
        "EMBEDDED_FILE_OF",
    ]
    source_sha256: str
    target_sha256: str
    evidence_refs: list[str] = Field(default_factory=list)
    member_name: str | None = None
    normalized_member_name: str | None = None
    analyzer_id: str | None = None
    extracted_at: datetime | None = None
    depth: int = 0
    member_index: int | None = None
    authority: Literal["AVBOX_ANALYSIS", "RAB", "USER_PROVIDED", "EXTERNAL_REFERENCE"] = (
        "AVBOX_ANALYSIS"
    )


class ExtractionBudget(BaseModel):
    max_recursion_depth: int
    max_children_per_object: int
    max_total_children: int
    max_single_child_bytes: int
    max_total_extracted_bytes: int
    max_expansion_ratio: float
    max_member_name_bytes: int
    max_path_depth: int
    max_extraction_time_seconds: int
    max_partitions_per_disk: int = 32
    max_materialized_partition_bytes: int = 256 * 1024 * 1024
    max_total_materialized_partition_bytes: int = 512 * 1024 * 1024


class ExtractionUsage(BaseModel):
    children_discovered: int = 0
    children_materialized: int = 0
    total_extracted_bytes: int = 0
    max_depth_reached: int = 0
    limit_events: list[str] = Field(default_factory=list)
    materialized_partition_bytes: int = 0


class RawOutputDescriptor(BaseModel):
    raw_output_id: str
    sha256: str | None = None
    size: int | None = None
    media_type: Literal["text/plain"] = "text/plain"


class StructuralValidation(BaseModel):
    validator: str
    format: str
    variant: str | None = None
    state: StructuralState
    observations: list[Observation] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    assessments: list[Assessment] = Field(default_factory=list)
    completeness: str = "COMPLETE"
    confidence: Confidence = Confidence.HIGH
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    validator_version: str
    duration_seconds: float
    error_state: str | None = None
    limit_state: str | None = None


class AnalyzerResult(BaseModel):
    analyzer_id: str
    analyzer_class: ScannerClass | str
    product: str
    implementation: str | None = None
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
    structural_validation: StructuralValidation | None = None


class DerivedObject(BaseModel):
    object: Any
    parent_sha256: str
    depth: int
    member_name: str | None = None
    normalized_member_name: str | None = None
    member_index: int | None = None
    extraction_status: str
    analyzer_results: list[AnalyzerResult] = Field(default_factory=list)
    scanner_results: list[Any] = Field(default_factory=list)
    normalized_verdict: Verdict = Verdict.NOT_SCANNED
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    preservation_context: PreservationContext = Field(default_factory=PreservationContext)
