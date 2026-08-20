from __future__ import annotations

import asyncio
import hashlib
import io
import json
from pathlib import Path

import httpx
import pytest
from test_m1_adapters import FakeAdapter

from avbox.api import create_app
from avbox.application import JobService, ScanService
from avbox.config import AppSettings, RABProtocolSettings
from avbox.models import (
    AnalysisResultEnvelope,
    ErrorCode,
    JobStatus,
    Observation,
    QualificationState,
    ScannerRuntimeStatus,
    Verdict,
)
from avbox.preservation import PreservationService
from avbox.protocol import RABClient, RABProtocolError, RABService
from avbox.registry import RegistryService
from avbox.runtime import Context

TOKEN = "test-token-not-a-production-secret"


def protocol_service(
    tmp_path: Path, *, capacity: int = 4, enabled: bool = True
) -> tuple[RABService, JobService]:
    credentials = tmp_path / "clients.json"
    credentials.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "client_id": "rab",
                        "token": TOKEN,
                        "scopes": ["analysis.submit", "analysis.read", "capabilities.read"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    credentials.chmod(0o600)
    jobs = JobService(tmp_path / "jobs.db")
    for analyzer in ("clamav", "yara"):
        jobs.save_scanner_status(
            ScannerRuntimeStatus(
                scanner_id=analyzer, qualification_state=QualificationState.QUALIFIED
            )
        )
    scans = ScanService(
        jobs=jobs,
        adapters={"clamav": FakeAdapter(), "yara": FakeAdapter()},
        system_adapters={},
        staging=tmp_path / "staging",
        quarantine=PreservationService(tmp_path / "quarantine"),
        maximum_file_bytes=4096,
    )
    settings = RABProtocolSettings(
        enabled=enabled,
        profiles_file=Path("config/analysis-profiles.yaml"),
        credential_file=credentials,
        upload_root=tmp_path / "uploads",
        maximum_upload_bytes=4096,
        queue_capacity=capacity,
        worker_concurrency=1,
    )
    settings.upload_root.mkdir(parents=True, exist_ok=True)
    service = RABService(
        settings=settings, jobs=jobs, scans=scans, raw_output_root=tmp_path / "raw"
    )
    return service, jobs


def submit(service: RABService, data: bytes, key: str = "key-1", **kwargs: str):
    return service.submit_stream(
        stream=io.BytesIO(data),
        client=RABClient("rab", frozenset({"analysis.submit"})),
        client_request_id=kwargs.get("client_request_id", "request-1"),
        idempotency_key=key,
        profile_id=kwargs.get("profile_id", "security-default@1"),
        expected_sha256=kwargs.get("expected_sha256", hashlib.sha256(data).hexdigest()),
        filename=kwargs.get("filename", "object.bin"),
        media_type="application/octet-stream",
    )


def test_protocol_models_keep_semantic_layers_separate() -> None:
    schema = AnalysisResultEnvelope.model_json_schema()
    properties = schema["properties"]
    assert {
        "observations",
        "findings",
        "assessments",
        "verdict",
        "preservation_context",
    } <= set(properties)
    assert Observation(observation_type="size", value=1, analyzer_id="identity").value == 1


def test_authentication_and_authorization(tmp_path: Path) -> None:
    service, _ = protocol_service(tmp_path)
    assert service.authenticate(f"Bearer {TOKEN}", "analysis.submit").client_id == "rab"
    with pytest.raises(RABProtocolError) as missing:
        service.authenticate(None, "analysis.submit")
    assert missing.value.code == ErrorCode.AUTHENTICATION_REQUIRED
    with pytest.raises(RABProtocolError):
        service.authenticate("Bearer wrong", "analysis.submit")
    with pytest.raises(RABProtocolError) as forbidden:
        service.authenticate(f"Bearer {TOKEN}", "admin")
    assert forbidden.value.code == ErrorCode.FORBIDDEN
    assert TOKEN not in str(forbidden.value)


def test_submit_async_result_and_clean_cleanup(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path)
    accepted = submit(service, b"harmless")
    assert accepted.state == JobStatus.QUEUED
    service.queue.join()
    job = jobs.get(str(accepted.job_id))
    assert job and job.status == JobStatus.COMPLETE
    result = service.results(str(accepted.job_id))
    assert result.verdict == Verdict.CLEAN
    assert result.observations[0].observation_type == "object_identity"
    record = jobs.rab_job(str(accepted.job_id))
    assert record and not Path(str(record["upload_path"])).exists()


def test_idempotency_and_conflict(tmp_path: Path) -> None:
    service, _ = protocol_service(tmp_path)
    first = submit(service, b"same", key="retry")
    second = submit(service, b"same", key="retry")
    assert first.job_id == second.job_id
    assert second.duplicate
    with pytest.raises(RABProtocolError) as conflict:
        submit(service, b"different", key="retry")
    assert conflict.value.code == ErrorCode.IDEMPOTENCY_CONFLICT


def test_hash_mismatch_rejected_before_job(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path)
    with pytest.raises(RABProtocolError) as mismatch:
        submit(service, b"bytes", expected_sha256="0" * 64)
    assert mismatch.value.code == ErrorCode.OBJECT_HASH_MISMATCH
    assert jobs.list() == []
    assert not list(service.settings.upload_root.glob("incoming-*"))


def test_upload_limit(tmp_path: Path) -> None:
    service, _ = protocol_service(tmp_path)
    service.settings.maximum_upload_bytes = 3
    with pytest.raises(RABProtocolError) as too_large:
        submit(service, b"four")
    assert too_large.value.code == ErrorCode.OBJECT_TOO_LARGE


def test_filename_is_metadata_and_cannot_traverse(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path)
    accepted = submit(service, b"safe", filename="../../etc/passwd")
    job = jobs.get(str(accepted.job_id))
    assert job and job.input_artifact.filename == "passwd"
    assert str(accepted.job_id) in str(jobs.rab_job(str(accepted.job_id))["upload_path"])  # type: ignore[index]


def test_unknown_profile_and_no_system_detectors(tmp_path: Path) -> None:
    service, _ = protocol_service(tmp_path)
    assert service.profiles()[0].analyzers == ["clamav", "yara"]
    with pytest.raises(RABProtocolError) as unsupported:
        submit(service, b"safe", profile_id="comprehensive@1")
    assert unsupported.value.code == ErrorCode.UNSUPPORTED_PROFILE


def test_unqualified_profile_analyzer_is_rejected(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path)
    jobs.save_scanner_status(
        ScannerRuntimeStatus(scanner_id="yara", qualification_state=QualificationState.DEGRADED)
    )
    with pytest.raises(RABProtocolError) as unavailable:
        submit(service, b"safe")
    assert unavailable.value.code == ErrorCode.ANALYZER_UNAVAILABLE


def test_queue_full_is_explicit(tmp_path: Path) -> None:
    service, _ = protocol_service(tmp_path, capacity=1, enabled=False)
    submit(service, b"first", key="first")
    with pytest.raises(RABProtocolError) as full:
        submit(service, b"second", key="second", client_request_id="request-2")
    assert full.value.code == ErrorCode.QUEUE_FULL


def test_restart_reconciles_queued_job(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path, enabled=False)
    accepted = submit(service, b"queued")
    assert jobs.get(str(accepted.job_id)).status == JobStatus.QUEUED  # type: ignore[union-attr]
    replacement = RABService(
        settings=service.settings, jobs=jobs, scans=service.scans, raw_output_root=tmp_path / "raw"
    )
    assert replacement.interrupted_jobs == 1
    assert jobs.get(str(accepted.job_id)).status == JobStatus.FAILED  # type: ignore[union-attr]
    assert not any(service.settings.upload_root.rglob("object"))


def test_graceful_shutdown_rejects_queued_work_and_removes_upload(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path, enabled=False)
    accepted = submit(service, b"queued for shutdown")
    service.shutdown()
    stopped = jobs.get(str(accepted.job_id))
    assert stopped is not None
    assert stopped.status == JobStatus.FAILED
    assert "graceful service shutdown" in stopped.errors[-1]
    assert not any(service.settings.upload_root.rglob("object"))


def test_capabilities_are_honest(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path)
    jobs.save_scanner_status(
        ScannerRuntimeStatus(
            scanner_id="clamav",
            qualification_state=QualificationState.QUALIFIED,
        )
    )
    jobs.save_scanner_status(
        ScannerRuntimeStatus(
            scanner_id="yara-x",
            qualification_state=QualificationState.QUALIFIED,
        )
    )
    capabilities = service.capabilities()
    assert capabilities["qualified_object_analyzers"] == ["clamav", "yara"]
    assert "yara-x" not in capabilities["qualified_object_analyzers"]
    assert capabilities["reference_resolution"] == "NOT_IMPLEMENTED"


def test_http_contract_auth_errors_and_openapi(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path)
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    context = Context(
        settings,
        RegistryService(Path("config/registry/registry.yaml")),
        jobs,
        {},
        {},
        service.scans,
        service,
    )
    app = create_app(context)

    async def qualify() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            missing = await http.get("/api/v1/rab/capabilities")
            assert missing.status_code == 401
            assert missing.json()["code"] == "AUTHENTICATION_REQUIRED"
            valid = await http.get(
                "/api/v1/rab/capabilities", headers={"Authorization": f"Bearer {TOKEN}"}
            )
            assert valid.status_code == 200
            schema = (await http.get("/openapi.json")).json()
            assert "/api/v1/rab/analysis-jobs" in schema["paths"]

    asyncio.run(qualify())


def test_http_streamed_upload_and_hash_mismatch(tmp_path: Path) -> None:
    service, jobs = protocol_service(tmp_path)
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    app = create_app(
        Context(
            settings,
            RegistryService(Path("config/registry/registry.yaml")),
            jobs,
            {},
            {},
            service.scans,
            service,
        )
    )
    headers = {"Authorization": f"Bearer {TOKEN}", "Idempotency-Key": "http-key"}
    data = b"http harmless"

    async def qualify() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
            response = await http.post(
                "/api/v1/rab/analysis-jobs",
                headers=headers,
                data={
                    "client_request_id": "http-1",
                    "expected_sha256": hashlib.sha256(data).hexdigest(),
                },
                files={"object_bytes": ("../../unsafe", data, "application/octet-stream")},
            )
            assert response.status_code == 202
            service.queue.join()
            results = await http.get(response.json()["links"]["results"], headers=headers)
            assert results.status_code == 200
            assert results.json()["verdict"] == "CLEAN"
            mismatch = await http.post(
                "/api/v1/rab/analysis-jobs",
                headers={**headers, "Idempotency-Key": "bad-hash"},
                data={"client_request_id": "http-2", "expected_sha256": "0" * 64},
                files={"object_bytes": ("x", data, "application/octet-stream")},
            )
            assert mismatch.status_code == 422
            assert mismatch.json()["code"] == "OBJECT_HASH_MISMATCH"

    asyncio.run(qualify())
