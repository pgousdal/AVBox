from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .artifacts import InputArtifact
from .common import FindingKind, HistoricalMode, QualificationState, ScanPolicy, Verdict


class JobStatus(StrEnum):
    CREATED = "CREATED"
    STAGED = "STAGED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    QUARANTINED = "QUARANTINED"


TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.CREATED: {JobStatus.STAGED, JobStatus.FAILED},
    JobStatus.STAGED: {JobStatus.QUEUED, JobStatus.FAILED, JobStatus.QUARANTINED},
    JobStatus.QUEUED: {JobStatus.RUNNING, JobStatus.FAILED},
    JobStatus.RUNNING: {JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.QUARANTINED},
    JobStatus.COMPLETE: {JobStatus.QUARANTINED},
    JobStatus.FAILED: set(),
    JobStatus.QUARANTINED: set(),
}


class ScannerResult(BaseModel):
    scanner_id: str
    native_verdict: str
    normalized_verdict: Verdict
    detection_name: str | None = None
    exit_code: int | None = None
    raw_output_ref: str
    engine_version: str | None = None
    definition_version: str | None = None
    definition_date: datetime | None = None
    runtime_profile: str
    scanned_at: datetime
    finding_kind: FindingKind | None = None
    definition_state: dict[str, str | int | None] = Field(default_factory=dict)
    duration_seconds: float | None = None
    selected_reason: str | None = None
    qualification_state: QualificationState | None = None


class ScanJob(BaseModel):
    job_id: UUID = Field(default_factory=uuid4)
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str
    input_artifact: InputArtifact
    requested_scanners: list[str]
    applicable_scanners: list[str] = Field(default_factory=list)
    platform_hints: list[str] = Field(default_factory=list)
    historical_mode: HistoricalMode | None = None
    detected_media_type: str | None = None
    status: JobStatus = JobStatus.CREATED
    scanner_results: list[ScannerResult] = Field(default_factory=list)
    normalized_verdict: Verdict = Verdict.NOT_SCANNED
    raw_output_refs: list[str] = Field(default_factory=list)
    preservation_decision: str | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    errors: list[str] = Field(default_factory=list)
    scan_policy: ScanPolicy = ScanPolicy.READ_ONLY

    def transition(self, target: JobStatus) -> None:
        if target not in TRANSITIONS[self.status]:
            raise ValueError(f"invalid job transition: {self.status} -> {target}")
        self.status = target
        self.updated_at = datetime.now(UTC)
