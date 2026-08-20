from __future__ import annotations

import bz2
import gzip
import lzma
import os
import shutil
import tarfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import IO, cast

from avbox.application.artifacts import ArtifactService
from avbox.config import AppSettings
from avbox.models import (
    DerivedObject,
    ExtractionBudget,
    ExtractionUsage,
    InputArtifact,
    ObjectIdentity,
    ObjectRelationship,
    QualificationState,
    Rights,
    RightsStatus,
    ScanJob,
)
from avbox.scanners.base import ProbeResult


@dataclass
class _Materialized:
    path: Path
    size: int


class ContainerAnalyzer:
    """Bounded userspace extraction and recursive application of existing analyzers."""

    analyzer_id = "container"
    supported_formats = ("zip", "tar", "gzip", "bzip2", "xz")

    def __init__(self, settings: AppSettings, scans: object):
        self.settings = settings
        self.scans = scans
        self.budget = ExtractionBudget(
            max_recursion_depth=settings.runtime.max_recursion_depth,
            max_children_per_object=settings.runtime.max_children_per_object,
            max_total_children=settings.runtime.max_total_children,
            max_single_child_bytes=settings.runtime.max_single_child_bytes,
            max_total_extracted_bytes=settings.runtime.max_total_extracted_bytes,
            max_expansion_ratio=settings.runtime.max_expansion_ratio,
            max_member_name_bytes=settings.runtime.max_member_name_bytes,
            max_path_depth=settings.runtime.max_path_depth,
            max_extraction_time_seconds=settings.runtime.max_extraction_time_seconds,
        )

    def probe(self) -> ProbeResult:
        return ProbeResult(
            True, "Python userspace bounded container handlers", QualificationState.PROBED, "stdlib"
        )

    def process(self, job: ScanJob, source: Path) -> None:
        usage = ExtractionUsage()
        job.extraction_budget = self.budget
        job.extraction_usage = usage
        started = time.monotonic()
        derived_root = self.settings.paths.staging / str(job.job_id) / "derived"
        derived_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            root_artifact = job.input_artifact
            self._process_object(
                job,
                source,
                root_artifact,
                depth=0,
                derived_root=derived_root,
                usage=usage,
                started=started,
            )
            if usage.limit_events and job.completeness == "COMPLETE":
                job.completeness = "PARTIAL_LIMIT"
        except (OSError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
            job.errors.append(f"container: {type(exc).__name__}: {exc}")
            job.completeness = "PARTIAL_ERROR"
        finally:
            shutil.rmtree(derived_root, ignore_errors=True)

    def _process_object(
        self,
        job: ScanJob,
        source: Path,
        parent: InputArtifact,
        *,
        depth: int,
        derived_root: Path,
        usage: ExtractionUsage,
        started: float,
    ) -> None:
        if time.monotonic() - started > self.budget.max_extraction_time_seconds:
            self._limit(job, usage, "EXTRACTION_TIME_LIMIT")
            return
        if depth >= self.budget.max_recursion_depth:
            return
        kind = self._kind(source)
        if kind is None:
            return
        if kind == "corrupt-zip":
            self._skip(job, usage, "CORRUPT_CONTAINER")
            job.completeness = "PARTIAL_ERROR"
            return
        if kind == "zip":
            with zipfile.ZipFile(source) as archive:
                infos = archive.infolist()
                if len(infos) > self.budget.max_children_per_object:
                    self._limit(job, usage, "CHILD_COUNT_LIMIT")
                for index, info in enumerate(infos[: self.budget.max_children_per_object]):
                    usage.children_discovered += 1
                    if not self._can_start_child(job, usage):
                        break
                    if info.flag_bits & 0x1:
                        self._skip(job, usage, "ENCRYPTED_CONTAINER")
                        continue
                    name = info.filename
                    if not self._safe_name(name):
                        self._skip(job, usage, "UNSAFE_MEMBER_PATH")
                        continue
                    if self._is_zip_link(info):
                        self._skip(job, usage, "SYMLINK_ENTRY")
                        continue
                    if info.file_size > self.budget.max_single_child_bytes:
                        self._skip(job, usage, "CHILD_SIZE_LIMIT")
                        continue
                    with archive.open(info, "r") as stream:
                        self._child(
                            job,
                            parent,
                            stream,
                            name,
                            index,
                            "CONTAINS",
                            depth,
                            source.stat().st_size,
                            derived_root,
                            usage,
                            started,
                        )
        elif kind == "tar":
            with tarfile.open(source, mode="r:*") as archive:
                members = archive.getmembers()
                if len(members) > self.budget.max_children_per_object:
                    self._limit(job, usage, "CHILD_COUNT_LIMIT")
                for index, member in enumerate(members[: self.budget.max_children_per_object]):
                    usage.children_discovered += 1
                    if not self._can_start_child(job, usage):
                        break
                    name = member.name
                    if not self._safe_name(name):
                        self._skip(job, usage, "UNSAFE_MEMBER_PATH")
                        continue
                    if member.issym() or member.islnk():
                        self._skip(job, usage, "SYMLINK_OR_HARDLINK_ENTRY")
                        continue
                    if not member.isfile():
                        self._skip(job, usage, "SPECIAL_FILE_ENTRY")
                        continue
                    if member.size > self.budget.max_single_child_bytes:
                        self._skip(job, usage, "CHILD_SIZE_LIMIT")
                        continue
                    member_stream = archive.extractfile(member)
                    if member_stream is not None:
                        with member_stream:
                            self._child(
                                job,
                                parent,
                                member_stream,
                                name,
                                index,
                                "CONTAINS",
                                depth,
                                source.stat().st_size,
                                derived_root,
                                usage,
                                started,
                            )
        else:
            opener: Callable[[Path], IO[bytes]]
            relation = "DECOMPRESSED_FROM"
            if kind == "gzip":
                opener = cast(Callable[[Path], IO[bytes]], gzip.open)
            elif kind == "bzip2":
                opener = cast(Callable[[Path], IO[bytes]], bz2.open)
            else:
                opener = cast(Callable[[Path], IO[bytes]], lzma.open)
            with opener(source) as stream:
                usage.children_discovered += 1
                self._child(
                    job,
                    parent,
                    stream,
                    f"decompressed.{kind}",
                    0,
                    relation,
                    depth,
                    source.stat().st_size,
                    derived_root,
                    usage,
                    started,
                )

    def _child(
        self,
        job: ScanJob,
        parent: InputArtifact,
        stream: IO[bytes],
        member_name: str,
        member_index: int,
        relation: str,
        parent_depth: int,
        parent_size: int,
        derived_root: Path,
        usage: ExtractionUsage,
        started: float,
    ) -> None:
        if not self._can_start_child(job, usage):
            return
        child_depth = parent_depth + 1
        target = derived_root / f"child-{usage.children_materialized:08d}"
        materialized = self._materialize(stream, target, parent_size, usage, job, started)
        if materialized is None:
            return
        usage.children_materialized += 1
        child_artifact = self._artifact(materialized.path, member_name)
        normalized = self._safe_display(member_name)
        child_job = self.scans.create_queued(  # type: ignore[attr-defined]
            artifact=child_artifact,
            source_label=f"derived:{job.job_id}",
            requested=[name for name in job.requested_scanners if name != self.analyzer_id],
        )
        child_result = self.scans.execute_queued(child_job, materialized.path)  # type: ignore[attr-defined]
        job.derived_objects.append(
            DerivedObject(
                object=ObjectIdentity(
                    sha256=child_artifact.hashes.sha256,
                    blake3=child_artifact.hashes.blake3,
                    sha1=child_artifact.hashes.sha1,
                    md5=child_artifact.hashes.md5,
                    size=child_artifact.byte_size,
                    filename=child_artifact.filename,
                    media_type=child_artifact.media_type,
                ),
                parent_sha256=parent.hashes.sha256,
                depth=child_depth,
                member_name=member_name,
                normalized_member_name=normalized,
                member_index=member_index,
                extraction_status="COMPLETE",
                analyzer_results=child_result.analyzer_results,
                scanner_results=child_result.scanner_results,
                normalized_verdict=child_result.normalized_verdict,
                errors=child_result.errors,
            )
        )
        job.relationships.append(
            ObjectRelationship(
                relationship=relation,  # type: ignore[arg-type]
                source_sha256=parent.hashes.sha256,
                target_sha256=child_artifact.hashes.sha256,
                member_name=member_name,
                normalized_member_name=normalized,
                analyzer_id=self.analyzer_id,
                extracted_at=datetime.now(UTC),
                depth=child_depth,
                member_index=member_index,
            )
        )
        usage.max_depth_reached = max(usage.max_depth_reached, child_depth)
        if child_depth >= self.budget.max_recursion_depth:
            self._limit(job, usage, "RECURSION_LIMIT_REACHED")
        else:
            self._process_object(
                job,
                materialized.path,
                child_artifact,
                depth=child_depth,
                derived_root=derived_root,
                usage=usage,
                started=started,
            )

    def _materialize(
        self,
        stream: IO[bytes],
        target: Path,
        parent_size: int,
        usage: ExtractionUsage,
        job: ScanJob,
        started: float,
    ) -> _Materialized | None:
        size = 0
        success = False
        try:
            with target.open("xb") as output:
                while chunk := stream.read(1024 * 1024):
                    if time.monotonic() - started > self.budget.max_extraction_time_seconds:
                        self._limit(job, usage, "EXTRACTION_TIME_LIMIT")
                        return None
                    if size + len(chunk) > self.budget.max_single_child_bytes:
                        self._limit(job, usage, "CHILD_SIZE_LIMIT")
                        return None
                    if (
                        usage.total_extracted_bytes + size + len(chunk)
                        > self.budget.max_total_extracted_bytes
                    ):
                        self._limit(job, usage, "EXTRACTION_BYTE_BUDGET_EXHAUSTED")
                        return None
                    if (
                        parent_size
                        and (size + len(chunk)) / parent_size > self.budget.max_expansion_ratio
                    ):
                        self._limit(job, usage, "EXPANSION_RATIO_LIMIT")
                        return None
                    output.write(chunk)
                    size += len(chunk)
                output.flush()
                os.fsync(output.fileno())
            target.chmod(0o400)
            usage.total_extracted_bytes += size
            success = True
            return _Materialized(target, size)
        finally:
            if target.exists() and not success:
                target.unlink(missing_ok=True)

    def _artifact(self, path: Path, name: str) -> InputArtifact:
        digest = ArtifactService.hash_file(path)
        return InputArtifact(
            hashes=digest.hashes,
            byte_size=digest.byte_size,
            filename=path.name,
            submitted_filename=name,
            media_type="application/octet-stream",
            source="derived-container",
            submitted_at=datetime.now(UTC),
            rights=Rights(redistribution_rights=RightsStatus.UNKNOWN),
        )

    @staticmethod
    def _kind(source: Path) -> str | None:
        if zipfile.is_zipfile(source):
            return "zip"
        try:
            with source.open("rb") as stream:
                header = stream.read(4)
        except OSError:
            return None
        if header.startswith(b"PK"):
            return "corrupt-zip"
        try:
            if tarfile.is_tarfile(source):
                return "tar"
        except (OSError, tarfile.TarError):
            pass
        with source.open("rb") as stream:
            header = stream.read(8)
        if header.startswith(b"\x1f\x8b"):
            return "gzip"
        if header.startswith(b"BZh"):
            return "bzip2"
        if header.startswith(b"\xfd7zXZ\x00"):
            return "xz"
        return None

    def _can_start_child(self, job: ScanJob, usage: ExtractionUsage) -> bool:
        if usage.children_materialized >= self.budget.max_total_children:
            self._limit(job, usage, "TOTAL_CHILD_COUNT_LIMIT")
            return False
        return True

    @staticmethod
    def _is_zip_link(info: zipfile.ZipInfo) -> bool:
        mode = (info.external_attr >> 16) & 0xFFFF
        return (mode & 0o170000) == 0o120000

    def _safe_name(self, name: str) -> bool:
        if len(name.encode("utf-8", errors="replace")) > self.budget.max_member_name_bytes:
            return False
        if "\x00" in name or name.startswith(("/", "\\")):
            return False
        if len(name) >= 2 and name[1] == ":":
            return False
        parts = [part for part in name.replace("\\", "/").split("/") if part]
        return len(parts) <= self.budget.max_path_depth and ".." not in parts

    @staticmethod
    def _safe_display(name: str) -> str:
        return PurePosixPath(name.replace("\\", "/")).as_posix()[:4096]

    @staticmethod
    def _limit(job: ScanJob, usage: ExtractionUsage, event: str) -> None:
        if event not in usage.limit_events:
            usage.limit_events.append(event)

    @staticmethod
    def _skip(job: ScanJob, usage: ExtractionUsage, event: str) -> None:
        if event not in usage.limit_events:
            usage.limit_events.append(event)
