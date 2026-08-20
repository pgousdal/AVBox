from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import tarfile
import zipfile
from pathlib import Path

from avbox.analyzers.containers import ContainerAnalyzer
from avbox.application.artifacts import ArtifactService
from avbox.config import AppSettings
from avbox.models import InputArtifact, JobStatus, ScanJob


def settings(tmp_path: Path, **runtime: object) -> AppSettings:
    root = tmp_path / "avbox"
    paths = {
        name: root / name
        for name in (
            "state",
            "staging",
            "jobs",
            "quarantine",
            "scratch",
            "raw_output",
            "rules",
            "registry",
        )
    }
    data = {
        "paths": paths,
        "storage": {"sqlite_path": root / "state" / "jobs.sqlite"},
        "rab": {"export_directory": root / "rab"},
        "rab_protocol": {
            "credential_file": root / "rab.json",
            "profiles_file": Path("config/analysis-profiles.yaml"),
            "upload_root": root / "uploads",
        },
        "runtime": runtime,
    }
    return AppSettings.model_validate(data)


class FakeScans:
    def create_queued(
        self, *, artifact: InputArtifact, source_label: str, requested: list[str]
    ) -> ScanJob:
        return ScanJob(source=source_label, input_artifact=artifact, requested_scanners=requested)

    def execute_queued(self, job: ScanJob, source: Path) -> ScanJob:
        del source
        job.status = JobStatus.COMPLETE
        return job


def root_job(source: Path) -> ScanJob:
    artifact = ArtifactService.hash_file(source)
    return ScanJob(
        source="test",
        input_artifact=artifact,
        requested_scanners=["container"],
        status=JobStatus.QUEUED,
    )


def run_container(tmp_path: Path, source: Path, **runtime: object) -> ScanJob:
    cfg = settings(tmp_path, **runtime)
    cfg.paths.staging.mkdir(parents=True, exist_ok=True)
    job = root_job(source)
    ContainerAnalyzer(cfg, FakeScans()).process(job, source)
    return job


def make_zip(path: Path, members: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in members:
            archive.writestr(name, value)


def test_zip_child_identity_relationship_and_cleanup(tmp_path: Path) -> None:
    source = tmp_path / "outer.zip"
    make_zip(source, [("hello.txt", b"hello")])
    job = run_container(tmp_path, source)
    assert len(job.derived_objects) == 1
    child = job.derived_objects[0]
    assert child.member_name == "hello.txt"
    assert child.parent_sha256 == job.input_artifact.hashes.sha256
    assert child.object.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert job.relationships[0].relationship == "CONTAINS"
    assert job.relationships[0].target_sha256 == child.object.sha256
    assert not (
        tmp_path / "avbox" / "staging" / str(job.job_id) / "derived"
    ).exists()


def test_nested_zip_and_depth_limit(tmp_path: Path) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("hello.txt", b"hello")
    source = tmp_path / "nested.zip"
    make_zip(source, [("inner.zip", inner.getvalue())])
    job = run_container(tmp_path, source, max_recursion_depth=1)
    assert [item.depth for item in job.derived_objects] == [1]
    assert "RECURSION_LIMIT_REACHED" in job.extraction_usage.limit_events
    assert job.completeness == "PARTIAL_LIMIT"


def test_duplicate_names_and_content_keep_edges(tmp_path: Path) -> None:
    source = tmp_path / "duplicates.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("same.txt", b"a")
        archive.writestr("same.txt", b"b")
        archive.writestr("copy.txt", b"b")
    job = run_container(tmp_path, source)
    assert len(job.derived_objects) == 3
    assert len(job.relationships) == 3
    assert job.derived_objects[1].object.sha256 == job.derived_objects[2].object.sha256


def test_unsafe_paths_and_tar_links_are_not_materialized(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.zip"
    make_zip(source, [("../../escape.txt", b"no"), ("/absolute.txt", b"no")])
    job = run_container(tmp_path, source)
    assert not job.derived_objects
    assert "UNSAFE_MEMBER_PATH" in job.extraction_usage.limit_events

    tar_path = tmp_path / "links.tar"
    with tarfile.open(tar_path, "w") as archive:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
    tar_job = run_container(tmp_path, tar_path)
    assert not tar_job.derived_objects
    assert "SYMLINK_OR_HARDLINK_ENTRY" in tar_job.extraction_usage.limit_events


def test_corrupt_zip_is_precise_partial_result(tmp_path: Path) -> None:
    source = tmp_path / "corrupt.zip"
    source.write_bytes(b"PK\x03\x04truncated")
    job = run_container(tmp_path, source)
    assert job.completeness == "PARTIAL_ERROR"
    assert "CORRUPT_CONTAINER" in job.extraction_usage.limit_events


def test_stream_compression_formats(tmp_path: Path) -> None:
    payload = b"payload" * 20
    for suffix, encoded in (
        (".gz", gzip.compress(payload)),
        (".bz2", bz2.compress(payload)),
        (".xz", lzma.compress(payload)),
    ):
        source = tmp_path / ("payload" + suffix)
        source.write_bytes(encoded)
        job = run_container(tmp_path, source)
        assert len(job.derived_objects) == 1
        assert job.derived_objects[0].object.size == len(payload)


def test_byte_and_child_budgets_are_global(tmp_path: Path) -> None:
    source = tmp_path / "many.zip"
    make_zip(source, [(f"{i}.txt", b"1234567890") for i in range(5)])
    job = run_container(
        tmp_path,
        source,
        max_children_per_object=2,
        max_total_children=2,
        max_total_extracted_bytes=12,
    )
    assert len(job.derived_objects) <= 2
    assert job.extraction_usage.total_extracted_bytes <= 12
    assert job.completeness == "PARTIAL_LIMIT"
