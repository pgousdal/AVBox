from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from avbox.analyzers import GenericAnalyzer
from avbox.models import (
    InputArtifact,
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
        generic_analyzers: dict[str, GenericAnalyzer] | None = None,
        staging: Path,
        quarantine: PreservationService,
        maximum_file_bytes: int,
    ):
        self.jobs = jobs
        self.adapters = adapters
        self.system_adapters = system_adapters
        self.generic_analyzers = generic_analyzers or {}
        self.staging = staging
        self.quarantine = quarantine
        self.maximum_file_bytes = maximum_file_bytes
        self.recursive_analyzer: object | None = None

    def scan_file(self, source: Path, requested: list[str]) -> ScanJob:
        if source.stat().st_size > self.maximum_file_bytes:
            raise ValueError("input exceeds configured maximum_file_bytes")
        artifact = ArtifactService.hash_file(source)
        selected = [
            name for name in requested if name in self.adapters or name in self.generic_analyzers
        ]
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
        return self.execute_queued(job, source)

    def create_queued(
        self, *, artifact: InputArtifact, source_label: str, requested: list[str]
    ) -> ScanJob:
        selected = [
            name for name in requested if name in self.adapters or name in self.generic_analyzers
        ]
        job = ScanJob(
            source=source_label,
            input_artifact=artifact,
            requested_scanners=requested,
            applicable_scanners=selected,
            detected_media_type="ordinary-file",
        )
        self.jobs.save(job)
        self.jobs.transition(job, JobStatus.STAGED)
        self.jobs.transition(job, JobStatus.QUEUED)
        return job

    def execute_queued(self, job: ScanJob, source: Path) -> ScanJob:
        if job.status != JobStatus.QUEUED:
            raise ValueError("job must be QUEUED before execution")
        self.jobs.transition(job, JobStatus.RUNNING)
        artifact = job.input_artifact
        requested = job.requested_scanners
        original = (artifact.byte_size, artifact.hashes.sha256)
        try:
            for name in requested:
                if name == "container":
                    continue
                generic = self.generic_analyzers.get(name)
                if generic is not None:
                    try:
                        generic_result = generic.analyze(artifact, source, str(job.job_id))
                        job.analyzer_results.append(generic_result)
                        if name == "document" and generic_result.native_status.startswith(
                            "partial_"
                        ):
                            job.completeness = generic_result.native_status.upper()
                        if generic_result.raw_output:
                            job.raw_output_refs.append(generic_result.raw_output.raw_output_id)
                        if generic_result.errors:
                            job.errors.extend(
                                f"{name}: {error}" for error in generic_result.errors
                            )
                            if name in {"executable", "document"} and not (
                                name == "document"
                                and generic_result.native_status.startswith("partial_")
                            ):
                                job.completeness = (
                                    "PARTIAL_LIMIT"
                                    if generic_result.native_status
                                    in {"partial_limit", "unsupported_limit"}
                                    else "PARTIAL_ERROR"
                                )
                        self.jobs.save_scanner_status(
                            ScannerRuntimeStatus(
                                scanner_id=name,
                                qualification_state=(
                                    generic_result.qualification_state
                                    or QualificationState.DEGRADED
                                ),
                                installed_version=(
                                    generic_result.engine_version
                                    or generic_result.product_version
                                ),
                                definition_state=generic_result.definition_state,
                                last_probe=datetime.now(UTC),
                                detail="generic object analysis completed",
                            )
                        )
                    except Exception as exc:
                        job.errors.append(f"{name}: {type(exc).__name__}: {exc}")
                    continue
                adapter = self.adapters.get(name)
                if adapter is None:
                    job.errors.append(f"{name}: unavailable or not applicable to ordinary files")
                    continue
                probe = adapter.probe()
                if not probe.available or probe.state != QualificationState.PROBED:
                    job.errors.append(f"{name}: {probe.detail}")
                    continue
                previous_status = self.jobs.scanner_statuses().get(name)
                self.jobs.save_scanner_status(
                    ScannerRuntimeStatus(
                        scanner_id=name,
                        qualification_state=(
                            QualificationState.QUALIFIED
                            if previous_status
                            and previous_status.qualification_state == QualificationState.QUALIFIED
                            else QualificationState.PROBED
                        ),
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
                    _, scanner_result = adapter.run_prepared(prepared)
                    scanner_result.selected_reason = (
                        "requested and runtime-capable for ordinary-file"
                    )
                    scanner_result.qualification_state = (
                        previous_status.qualification_state if previous_status else probe.state
                    )
                    job.scanner_results.append(scanner_result)
                    job.raw_output_refs.append(scanner_result.raw_output_ref)
                    self.jobs.save_scanner_status(
                        ScannerRuntimeStatus(
                            scanner_id=name,
                            qualification_state=(
                                QualificationState.DEGRADED
                                if scanner_result.normalized_verdict == Verdict.ERROR
                                else QualificationState.QUALIFIED
                            ),
                            installed_version=scanner_result.engine_version,
                            definition_state=scanner_result.definition_state,
                            last_probe=datetime.now(UTC),
                            detail="real ordinary-file execution completed",
                        )
                    )
                finally:
                    adapter.cleanup(prepared)
            job.root_verdict = aggregate_verdict(job.scanner_results)
            job.normalized_verdict = job.root_verdict
            if "container" in requested and self.recursive_analyzer is not None:
                self.recursive_analyzer.process(job, source)  # type: ignore[attr-defined]
                child_results = [
                    result for child in job.derived_objects for result in child.scanner_results
                ]
                job.normalized_verdict = aggregate_verdict(job.scanner_results + child_results)
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
