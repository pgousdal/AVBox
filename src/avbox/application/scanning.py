from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from avbox.models import (
    JobStatus,
    QualificationState,
    ScanJob,
    ScannerResult,
    ScannerRuntimeStatus,
    Verdict,
)
from avbox.preservation import PreservationService
from avbox.scanners.base import ScannerAdapter, SystemDetectorAdapter

from .artifacts import ArtifactService
from .jobs import JobService


def aggregate_verdict(results: list[ScannerResult]) -> Verdict:
    """Conservative precedence: errors prevent an all-clean claim, matches always win."""
    verdicts = {result.normalized_verdict for result in results}
    for verdict in (Verdict.MALICIOUS, Verdict.PUA, Verdict.SUSPICIOUS):
        if verdict in verdicts:
            return verdict
    if Verdict.ERROR in verdicts:
        return Verdict.ERROR if verdicts == {Verdict.ERROR} else Verdict.UNKNOWN
    if Verdict.CLEAN in verdicts:
        return Verdict.CLEAN
    if Verdict.UNKNOWN in verdicts:
        return Verdict.UNKNOWN
    if Verdict.UNSUPPORTED in verdicts:
        return Verdict.UNSUPPORTED
    return Verdict.NOT_SCANNED


class ScanService:
    def __init__(
        self,
        *,
        jobs: JobService,
        adapters: dict[str, ScannerAdapter],
        system_adapters: dict[str, SystemDetectorAdapter],
        staging: Path,
        quarantine: PreservationService,
        maximum_file_bytes: int,
    ):
        self.jobs = jobs
        self.adapters = adapters
        self.system_adapters = system_adapters
        self.staging = staging
        self.quarantine = quarantine
        self.maximum_file_bytes = maximum_file_bytes

    def scan_file(self, source: Path, requested: list[str]) -> ScanJob:
        if source.stat().st_size > self.maximum_file_bytes:
            raise ValueError("input exceeds configured maximum_file_bytes")
        artifact = ArtifactService.hash_file(source)
        selected = [name for name in requested if name in self.adapters]
        job = ScanJob(
            source="local-cli",
            input_artifact=artifact,
            requested_scanners=requested,
            applicable_scanners=selected,
            detected_media_type="ordinary-file",
        )
        self.jobs.save(job)
        self.jobs.transition(job, JobStatus.STAGED)
        self.jobs.transition(job, JobStatus.QUEUED)
        self.jobs.transition(job, JobStatus.RUNNING)
        original = (artifact.byte_size, artifact.hashes.sha256)
        try:
            for name in requested:
                adapter = self.adapters.get(name)
                if adapter is None:
                    job.errors.append(f"{name}: unavailable or not applicable to ordinary files")
                    continue
                probe = adapter.probe()
                if not probe.available:
                    job.errors.append(f"{name}: {probe.detail}")
                    continue
                self.jobs.save_scanner_status(
                    ScannerRuntimeStatus(
                        scanner_id=name,
                        qualification_state=QualificationState.PROBED,
                        installed_version=probe.version,
                        definition_state=probe.definition_state or {},
                        last_probe=datetime.now(UTC),
                        detail=probe.detail,
                    )
                )
                prepared = adapter.prepare(
                    job_id=str(job.job_id), immutable_input=source, working_root=self.staging
                )
                try:
                    _, result = adapter.run_prepared(prepared)
                    result.selected_reason = "requested and runtime-capable for ordinary-file"
                    job.scanner_results.append(result)
                    job.raw_output_refs.append(result.raw_output_ref)
                    self.jobs.save_scanner_status(
                        ScannerRuntimeStatus(
                            scanner_id=name,
                            qualification_state=(
                                QualificationState.DEGRADED
                                if result.normalized_verdict == Verdict.ERROR
                                else QualificationState.QUALIFIED
                            ),
                            installed_version=result.engine_version,
                            definition_state=result.definition_state,
                            last_probe=datetime.now(UTC),
                            detail="real ordinary-file execution completed",
                        )
                    )
                finally:
                    adapter.cleanup(prepared)
            job.normalized_verdict = aggregate_verdict(job.scanner_results)
            if (source.stat().st_size, ArtifactService.hash_file(source).hashes.sha256) != original:
                raise RuntimeError("READ_ONLY invariant violated: source changed during scan")
            if job.normalized_verdict in {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.PUA}:
                path = self.quarantine.admit(source, artifact, job.normalized_verdict)
                job.preservation_decision = f"local-quarantine:{path.name}"
                self.jobs.transition(job, JobStatus.QUARANTINED)
            else:
                job.preservation_decision = "transient-bytes-removed"
                self.jobs.transition(job, JobStatus.COMPLETE)
        except Exception as exc:
            job.errors.append(str(exc))
            self.jobs.transition(job, JobStatus.FAILED)
        finally:
            job_root = self.staging / str(job.job_id)
            if job_root.exists():
                shutil.rmtree(job_root)
            self.jobs.save(job)
        return job

    def system_scan(self, requested: list[str]) -> list[ScannerResult]:
        results: list[ScannerResult] = []
        for name in requested:
            adapter = self.system_adapters.get(name)
            if adapter is None:
                continue
            if not adapter.probe().available:
                continue
            _, result = adapter.normalize(adapter.system_scan())
            results.append(result)
            self.jobs.save_scanner_status(
                ScannerRuntimeStatus(
                    scanner_id=name,
                    qualification_state=(
                        QualificationState.DEGRADED
                        if result.normalized_verdict == Verdict.ERROR
                        else QualificationState.QUALIFIED
                    ),
                    installed_version=adapter.probe().version,
                    last_probe=datetime.now(UTC),
                    detail="real system execution completed",
                )
            )
        return results
