from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from avbox.models import (
    Hashes,
    InputArtifact,
    JobStatus,
    RepairRecord,
    Rights,
    RightsStatus,
    ScanJob,
    ScanPolicy,
    Verdict,
)

HASHES = Hashes(sha256="a" * 64, blake3="b" * 64, sha1="c" * 40, md5="d" * 32)


def artifact() -> InputArtifact:
    return InputArtifact(
        hashes=HASHES,
        byte_size=1,
        filename="not-identity.bin",
        media_type="application/octet-stream",
        source="test",
        submitted_at=datetime.now(UTC),
    )


def test_job_state_machine() -> None:
    job = ScanJob(source="test", input_artifact=artifact(), requested_scanners=[])
    for status in (JobStatus.STAGED, JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.COMPLETE):
        job.transition(status)
    assert job.status is JobStatus.COMPLETE


def test_invalid_job_transition_fails() -> None:
    job = ScanJob(source="test", input_artifact=artifact(), requested_scanners=[])
    with pytest.raises(ValueError, match="invalid job transition"):
        job.transition(JobStatus.RUNNING)


def test_verdict_and_default_read_only() -> None:
    assert Verdict.PUA.value == "PUA"
    assert (
        ScanJob(source="test", input_artifact=artifact(), requested_scanners=[]).scan_policy
        is ScanPolicy.READ_ONLY
    )


def test_repair_cannot_target_original() -> None:
    with pytest.raises(ValidationError, match="immutable original"):
        RepairRecord(
            source_artifact_hash="a" * 64,
            working_copy_hash="a" * 64,
            scanner_id="x",
            repair_action="repair",
            repaired_artifact_hash="e" * 64,
            scanner_output_ref="raw/1",
            timestamp=datetime.now(UTC),
        )


def test_rights_default_unknown() -> None:
    assert Rights().redistribution_rights is RightsStatus.UNKNOWN
