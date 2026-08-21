from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

import blake3
import yaml

from avbox.application import ArtifactService, JobService, ScanService
from avbox.config import RABProtocolSettings
from avbox.models import (
    AnalysisJobAccepted,
    AnalysisJobStatus,
    AnalysisProfile,
    AnalysisResultEnvelope,
    AnalyzerResult,
    ErrorCode,
    Finding,
    Hashes,
    InputArtifact,
    JobStatus,
    ObjectIdentity,
    Observation,
    PreservationContext,
    QualificationState,
    RawOutputDescriptor,
    Rights,
    ScanJob,
    ScannerClass,
)


@dataclass(frozen=True)
class RABClient:
    client_id: str
    scopes: frozenset[str]


class RABProtocolError(Exception):
    def __init__(self, status_code: int, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail


logger = logging.getLogger("avbox.rab")


class RABService:
    def __init__(
        self,
        *,
        settings: RABProtocolSettings,
        jobs: JobService,
        scans: ScanService,
        raw_output_root: Path,
    ):
        self.settings = settings
        self.jobs = jobs
        self.scans = scans
        self.raw_output_root = raw_output_root
        self.profile_map = self._load_profiles(settings.profiles_file)
        self.queue: queue.Queue[tuple[ScanJob, Path] | None] = queue.Queue(
            maxsize=settings.queue_capacity
        )
        self.lock = threading.Lock()
        self.interrupted_jobs = jobs.reconcile_interrupted()
        self._clean_interrupted_uploads()
        self.workers: list[threading.Thread] = []
        if settings.enabled:
            settings.upload_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            for number in range(settings.worker_concurrency):
                worker = threading.Thread(
                    target=self._worker, name=f"avbox-rab-{number}", daemon=True
                )
                worker.start()
                self.workers.append(worker)

    def shutdown(self) -> None:
        while True:
            try:
                pending = self.queue.get_nowait()
            except queue.Empty:
                break
            if pending is not None:
                job, upload = pending
                job.errors.append("ANALYSIS_FAILED: interrupted by graceful service shutdown")
                job.transition(JobStatus.FAILED)
                self.jobs.save(job)
                self._remove_upload(upload)
            self.queue.task_done()
        for _ in self.workers:
            self.queue.put(None)
        for worker in self.workers:
            worker.join()

    def authenticate(self, authorization: str | None, required_scope: str) -> RABClient:
        if not authorization or not authorization.startswith("Bearer "):
            logger.warning("rab_authentication_failed reason=missing")
            raise RABProtocolError(
                401, ErrorCode.AUTHENTICATION_REQUIRED, "a bearer credential is required"
            )
        supplied = authorization.removeprefix("Bearer ")
        try:
            document = json.loads(self.settings.credential_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RABProtocolError(
                503, ErrorCode.STORAGE_UNAVAILABLE, "credential store is unavailable"
            ) from exc
        for value in document.get("clients", []):
            token = str(value.get("token", ""))
            if token and hmac.compare_digest(supplied, token):
                client = RABClient(str(value["client_id"]), frozenset(value.get("scopes", [])))
                if required_scope not in client.scopes:
                    logger.warning(
                        "rab_authorization_failed client_id=%s scope=%s",
                        client.client_id,
                        required_scope,
                    )
                    raise RABProtocolError(
                        403, ErrorCode.FORBIDDEN, "client lacks the required scope"
                    )
                return client
        logger.warning("rab_authentication_failed reason=invalid")
        raise RABProtocolError(401, ErrorCode.AUTHENTICATION_REQUIRED, "credential is invalid")

    def profiles(self) -> list[AnalysisProfile]:
        return list(self.profile_map.values())

    def capabilities(self) -> dict[str, object]:
        recursive = getattr(self.scans, "recursive_analyzer", None)
        installed = self.jobs.scanner_statuses()
        qualified = sorted(
            name
            for name, state in installed.items()
            if state.qualification_state == QualificationState.QUALIFIED
            and name in {"clamav", "yara"}
        )
        return {
            "protocol_versions": ["1"],
            "profiles": [profile.qualified_id for profile in self.profiles()],
            "qualified_object_analyzers": qualified,
            "qualified_generic_analyzers": sorted(
                name
                for name in self.scans.generic_analyzers
                if name in installed
                and installed[name].qualification_state == QualificationState.QUALIFIED
            ),
            "available_generic_analyzers": sorted(
                name
                for name, analyzer in self.scans.generic_analyzers.items()
                if analyzer.probe().available
            ),
            "maximum_upload_bytes": self.settings.maximum_upload_bytes,
            "submission_modes": ["byte-upload", "external-reference-metadata-only"],
            "reference_resolution": "NOT_IMPLEMENTED",
            "rab_correlation": "NOT_AVAILABLE",
            "recursive_analysis": "QUALIFIED" if recursive is not None else "NOT_AVAILABLE",
            "container_analysis": {
                "state": "QUALIFIED" if recursive is not None else "UNAVAILABLE",
                "formats": ["zip", "tar", "gzip", "bzip2", "xz", "lha", "iso9660", "7z", "cab", "arj"],  # noqa: E501
                "handlers": {
                    "zip": {"recognize": True, "extract": True, "qualified": True, "handler": "python-stdlib"},  # noqa: E501
                    "tar": {"recognize": True, "extract": True, "qualified": True, "handler": "python-stdlib"},  # noqa: E501
                    "gzip": {"recognize": True, "extract": True, "qualified": True, "handler": "python-stdlib"},  # noqa: E501
                    "bzip2": {"recognize": True, "extract": True, "qualified": True, "handler": "python-stdlib"},  # noqa: E501
                    "xz": {"recognize": True, "extract": True, "qualified": True, "handler": "python-stdlib"},  # noqa: E501
                    "lha": {"recognize": True, "extract": True, "qualified": True, "handler": "lhasa-0.5.0"},  # noqa: E501
                    "iso9660": {"recognize": True, "extract": True, "qualified": True, "handler": "7zip-26.00-userspace"},  # noqa: E501
                    "7z": {"recognize": True, "extract": True, "qualified": True, "handler": "7zip-26.00"},  # noqa: E501
                    "cab": {"recognize": True, "extract": True, "qualified": True, "handler": "7zip-26.00"},  # noqa: E501
                    "arj": {"recognize": True, "extract": True, "qualified": True, "handler": "7zip-26.00"},  # noqa: E501
                    "lzx": {"recognize": False, "extract": False, "qualified": False, "status": "DEFERRED"},  # noqa: E501
                    "rar": {"recognize": True, "extract": False, "qualified": False, "status": "DEFERRED"},  # noqa: E501
                },
                "budgets": recursive.budget.model_dump(mode="json") if recursive else None,
            },
            "queue_capacity": self.settings.queue_capacity,
            "child_object_graph": recursive is not None,
        }

    def submit_stream(
        self,
        *,
        stream: BinaryIO,
        client: RABClient,
        client_request_id: str,
        idempotency_key: str,
        profile_id: str,
        expected_sha256: str,
        filename: str | None,
        media_type: str | None,
    ) -> AnalysisJobAccepted:
        profile = self.profile_map.get(profile_id)
        if not profile or not profile.enabled:
            raise RABProtocolError(422, ErrorCode.UNSUPPORTED_PROFILE, "profile is unsupported")
        if not idempotency_key or len(idempotency_key) > 200:
            raise RABProtocolError(
                422,
                ErrorCode.INVALID_REQUEST,
                "Idempotency-Key is required and must be at most 200 characters",
            )
        if not client_request_id or len(client_request_id) > 200:
            raise RABProtocolError(422, ErrorCode.INVALID_REQUEST, "client_request_id is required")
        incoming = self.settings.upload_root / f"incoming-{uuid4().hex}"
        hashes = {name: hashlib.new(name) for name in ("sha256", "sha1", "md5")}
        b3 = blake3.blake3()
        size = 0
        try:
            with incoming.open("xb") as output:
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > self.settings.maximum_upload_bytes:
                        raise RABProtocolError(
                            413, ErrorCode.OBJECT_TOO_LARGE, "upload exceeds configured maximum"
                        )
                    output.write(chunk)
                    for digest in hashes.values():
                        digest.update(chunk)
                    b3.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            actual_sha256 = hashes["sha256"].hexdigest()
            if not hmac.compare_digest(actual_sha256, expected_sha256.lower()):
                logger.warning(
                    "rab_hash_mismatch client_id=%s actual_sha256=%s",
                    client.client_id,
                    actual_sha256,
                )
                raise RABProtocolError(
                    422,
                    ErrorCode.OBJECT_HASH_MISMATCH,
                    "declared SHA-256 does not match received bytes",
                )
            fingerprint = hashlib.sha256(
                f"{client.client_id}\0{client_request_id}\0{profile_id}\0{actual_sha256}".encode()
            ).hexdigest()
            idempotency_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
            with self.lock:
                existing = self.jobs.rab_by_idempotency(client.client_id, idempotency_hash)
                if existing:
                    if existing["fingerprint"] != fingerprint:
                        raise RABProtocolError(
                            409,
                            ErrorCode.IDEMPOTENCY_CONFLICT,
                            "idempotency key was reused with different semantics",
                        )
                    incoming.unlink(missing_ok=True)
                    return self.accepted(str(existing["job_id"]), duplicate=True)
                runtime = self.jobs.scanner_statuses()
                unavailable = [
                    analyzer
                    for analyzer in profile.analyzers
                    if not self._analyzer_available(analyzer, runtime)
                ]
                if unavailable:
                    raise RABProtocolError(
                        503,
                        ErrorCode.ANALYZER_UNAVAILABLE,
                        "profile analyzers are not qualified and available: "
                        + ", ".join(unavailable),
                    )
                if self.queue.full():
                    logger.warning(
                        "rab_queue_rejected client_id=%s sha256=%s", client.client_id, actual_sha256
                    )
                    raise RABProtocolError(
                        429, ErrorCode.QUEUE_FULL, "analysis queue is at capacity"
                    )
                incoming.chmod(0o400)
                safe_filename = self._safe_label(filename)
                artifact = InputArtifact(
                    hashes=Hashes(
                        sha256=actual_sha256,
                        blake3=b3.hexdigest(),
                        sha1=hashes["sha1"].hexdigest(),
                        md5=hashes["md5"].hexdigest(),
                    ),
                    byte_size=size,
                    filename=safe_filename or "submitted-object",
                    submitted_filename=(filename[:1024] if filename else None),
                    media_type=media_type or "application/octet-stream",
                    source=f"rab:{client.client_id}",
                    submitted_at=datetime.now(UTC),
                    rights=Rights(),
                )
                job = self.scans.create_queued(
                    artifact=artifact,
                    source_label=f"rab:{client.client_id}",
                    requested=profile.analyzers,
                )
                directory = self.settings.upload_root / str(job.job_id)
                directory.mkdir(mode=0o700)
                upload = directory / "object"
                incoming.rename(upload)
                self.jobs.save_rab_job(
                    job_id=str(job.job_id),
                    client_id=client.client_id,
                    client_request_id=client_request_id,
                    idempotency_key=idempotency_hash,
                    fingerprint=fingerprint,
                    profile=profile_id,
                    upload_path=str(upload),
                    document={
                        "declared_sha256": expected_sha256.lower(),
                        "verified_sha256": actual_sha256,
                        "size": size,
                        "filename": safe_filename,
                        "media_type": media_type,
                    },
                )
                self.queue.put_nowait((job, upload))
                logger.info(
                    "rab_job_accepted client_id=%s job_id=%s sha256=%s profile=%s",
                    client.client_id,
                    job.job_id,
                    actual_sha256,
                    profile_id,
                )
            return self.accepted(str(job.job_id))
        except Exception:
            incoming.unlink(missing_ok=True)
            raise

    def accepted(self, job_id: str, duplicate: bool = False) -> AnalysisJobAccepted:
        job = self.jobs.get(job_id)
        record = self.jobs.rab_job(job_id)
        if not job or not record:
            raise RABProtocolError(404, ErrorCode.NOT_FOUND, "analysis job was not found")
        profile = str(record["profile"])
        return AnalysisJobAccepted(
            job_id=job.job_id,
            object_id=f"sha256:{job.input_artifact.hashes.sha256}",
            object_sha256=job.input_artifact.hashes.sha256,
            profile=profile,
            state=job.status,
            created_at=job.submitted_at,
            duplicate=duplicate,
            links={
                "self": f"/api/v1/rab/analysis-jobs/{job.job_id}",
                "results": f"/api/v1/rab/analysis-jobs/{job.job_id}/results",
            },
        )

    def status(self, job_id: str) -> AnalysisJobStatus:
        job = self.jobs.get(job_id)
        record = self.jobs.rab_job(job_id)
        if not job or not record:
            raise RABProtocolError(404, ErrorCode.NOT_FOUND, "analysis job was not found")
        return AnalysisJobStatus(
            job_id=job.job_id,
            object_sha256=job.input_artifact.hashes.sha256,
            profile=str(record["profile"]),
            state=job.status,
            created_at=job.submitted_at,
            updated_at=job.updated_at,
            client_request_id=str(record["client_request_id"]),
        )

    def results(self, job_id: str) -> AnalysisResultEnvelope:
        job = self.jobs.get(job_id)
        record = self.jobs.rab_job(job_id)
        if not job or not record:
            raise RABProtocolError(404, ErrorCode.NOT_FOUND, "analysis job was not found")
        artifact = job.input_artifact
        analyzers = list(job.analyzer_results) + [
            self._map_result(item) for item in job.scanner_results
        ]
        findings = [finding for analyzer in analyzers for finding in analyzer.findings]
        observations = [value for analyzer in analyzers for value in analyzer.observations]
        assessments = [value for analyzer in analyzers for value in analyzer.assessments]
        analyzer_starts = [item.started_at for item in analyzers if item.started_at is not None]
        return AnalysisResultEnvelope(
            job_id=job.job_id,
            object=ObjectIdentity(
                sha256=artifact.hashes.sha256,
                blake3=artifact.hashes.blake3,
                sha1=artifact.hashes.sha1,
                md5=artifact.hashes.md5,
                size=artifact.byte_size,
                filename=artifact.filename,
                media_type=artifact.media_type,
            ),
            profile=str(record["profile"]),
            state=job.status,
            started_at=min(analyzer_starts) if analyzer_starts else None,
            completed_at=job.updated_at
            if job.status in {JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.QUARANTINED}
            else None,
            analyzers=analyzers,
            observations=[
                Observation(
                    observation_type="object_identity",
                    analyzer_id="avbox.identity",
                    value={"sha256": artifact.hashes.sha256, "size": artifact.byte_size},
                )
            ]
            + observations,
            findings=findings,
            assessments=assessments,
            verdict=job.normalized_verdict if job.scanner_results else None,
            derived_objects=job.derived_objects,
            relationships=job.relationships,
            completeness=job.completeness,
            extraction_budget=job.extraction_budget,
            extraction_usage=job.extraction_usage,
            preservation_context=PreservationContext(
                provenance={
                    "client_id": record["client_id"],
                    "client_request_id": record["client_request_id"],
                    "profile": record["profile"],
                }
            ),
            errors=job.errors,
            provenance={
                "requested_by": record["client_id"],
                "verified_sha256": artifact.hashes.sha256,
                "scan_policy": job.scan_policy,
                "root_verdict": job.root_verdict,
            },
        )

    def _analyzer_available(self, analyzer_id: str, runtime: Mapping[str, object]) -> bool:
        if analyzer_id == "container":
            return self.scans.recursive_analyzer is not None
        generic = self.scans.generic_analyzers.get(analyzer_id)
        if generic is not None:
            probe = generic.probe()
            return probe.available and probe.state in {
                QualificationState.PROBED,
                QualificationState.QUALIFIED,
            }
        return (
            analyzer_id in self.scans.adapters
            and analyzer_id in runtime
            and getattr(runtime[analyzer_id], "qualification_state", None)
            == QualificationState.QUALIFIED
        )

    def _map_result(self, result: object) -> AnalyzerResult:
        from avbox.models import ScannerResult

        if not isinstance(result, ScannerResult):
            raise TypeError("expected ScannerResult")
        product = "ClamAV" if result.scanner_id == "clamav" else "YARA"
        analyzer_class = (
            ScannerClass.ANTIVIRUS_ENGINE
            if result.scanner_id == "clamav"
            else ScannerClass.RULE_ENGINE
        )
        findings = []
        if result.detection_name or result.finding_kind:
            findings.append(
                Finding(
                    finding_type=str(result.finding_kind or "detector_finding"),
                    analyzer_id=result.scanner_id,
                    native_name=result.detection_name,
                    normalized_verdict=result.normalized_verdict,
                    evidence_refs=[result.raw_output_ref],
                )
            )
        started_at = (
            result.scanned_at - timedelta(seconds=result.duration_seconds)
            if result.duration_seconds is not None
            else None
        )
        return AnalyzerResult(
            analyzer_id=result.scanner_id,
            analyzer_class=analyzer_class,
            product=product,
            engine_version=result.engine_version,
            definition_state=result.definition_state,
            qualification_state=result.qualification_state,
            started_at=started_at,
            completed_at=result.scanned_at,
            duration_seconds=result.duration_seconds,
            execution_profile=result.runtime_profile,
            native_status=result.native_verdict,
            native_exit_code=result.exit_code,
            normalized_verdict=result.normalized_verdict,
            findings=findings,
            raw_output=self._raw_descriptor(result.raw_output_ref),
        )

    def _raw_descriptor(self, reference: str) -> RawOutputDescriptor:
        relative = reference.removeprefix("raw-output/")
        path = self.raw_output_root / relative
        if not path.is_file():
            return RawOutputDescriptor(raw_output_id=reference)
        digest = ArtifactService.hash_file(path)
        return RawOutputDescriptor(
            raw_output_id=reference, sha256=digest.hashes.sha256, size=digest.byte_size
        )

    @staticmethod
    def _safe_label(value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = "".join(character for character in value if character.isprintable())[:255]
        return Path(cleaned).name or None

    def _worker(self) -> None:
        while True:
            item = self.queue.get()
            if item is None:
                self.queue.task_done()
                return
            job, upload = item
            try:
                self.scans.execute_queued(job, upload)
                completed = self.jobs.get(str(job.job_id))
                logger.info(
                    "rab_job_completed job_id=%s state=%s",
                    job.job_id,
                    completed.status if completed else "UNKNOWN",
                )
            except Exception as exc:
                current = self.jobs.get(str(job.job_id)) or job
                current.errors.append(f"ANALYSIS_FAILED: {exc}")
                if current.status != JobStatus.FAILED:
                    current.transition(JobStatus.FAILED)
                self.jobs.save(current)
                logger.error(
                    "rab_job_failed job_id=%s error_type=%s", job.job_id, type(exc).__name__
                )
            finally:
                self._remove_upload(upload)
                self.queue.task_done()

    def _clean_interrupted_uploads(self) -> None:
        if not self.interrupted_jobs:
            return
        for job in self.jobs.list():
            if "ANALYSIS_FAILED: interrupted by service restart" not in job.errors:
                continue
            record = self.jobs.rab_job(str(job.job_id))
            upload_path = record.get("upload_path") if record else None
            if isinstance(upload_path, str):
                self._remove_upload(Path(upload_path))

    def _remove_upload(self, upload: Path) -> None:
        root = self.settings.upload_root.resolve()
        candidate = upload.resolve()
        if not candidate.is_relative_to(root):
            logger.error("rab_upload_cleanup_refused path_outside_upload_root")
            return
        candidate.unlink(missing_ok=True)
        try:
            candidate.parent.rmdir()
        except OSError:
            pass

    @staticmethod
    def _load_profiles(path: Path) -> dict[str, AnalysisProfile]:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        profiles = [AnalysisProfile.model_validate(item) for item in document["profiles"]]
        values = {profile.qualified_id: profile for profile in profiles}
        if len(values) != len(profiles):
            raise ValueError("duplicate qualified analysis profile ID")
        return values
