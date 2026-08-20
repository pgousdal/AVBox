from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path, PurePath

from avbox.config import AppSettings
from avbox.models import (
    AnalyzerResult,
    Assessment,
    Confidence,
    InputArtifact,
    Observation,
    QualificationState,
    RawOutputDescriptor,
    ScannerClass,
)
from avbox.scanners.base import ProbeResult
from avbox.scanners.command import CommandResult, IsolatedCommandRunner, store_raw_output

COMPOUND_EXTENSIONS = {"tar.gz", "tar.bz2", "tar.xz", "tar.zst"}
EXTENSION_FAMILIES = {
    "txt": "text",
    "md": "text",
    "csv": "text",
    "json": "text",
    "xml": "text",
    "png": "image",
    "jpg": "image",
    "jpeg": "image",
    "gif": "image",
    "pdf": "document",
    "doc": "document",
    "docx": "document",
    "zip": "container",
    "gz": "container",
    "lha": "container",
    "lzh": "container",
    "iso": "container",
    "adf": "container",
    "exe": "executable",
    "com": "executable",
    "scr": "executable",
    "elf": "executable",
}


class GenericAnalyzer(ABC):
    analyzer_id: str
    analyzer_class: ScannerClass
    product: str

    @abstractmethod
    def probe(self) -> ProbeResult: ...

    @abstractmethod
    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult: ...


class IdentityAnalyzer(GenericAnalyzer):
    analyzer_id = "identity"
    analyzer_class = ScannerClass.IDENTITY_ANALYZER
    product = "AVBox Identity"

    def probe(self) -> ProbeResult:
        return ProbeResult(
            True, "built-in exact ingestion identity", QualificationState.PROBED, "1"
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        del source, job_id
        started = datetime.now(UTC)
        values = {
            "identity.sha256": artifact.hashes.sha256,
            "identity.blake3": artifact.hashes.blake3,
            "identity.sha1": artifact.hashes.sha1,
            "identity.md5": artifact.hashes.md5,
            "object.size": artifact.byte_size,
        }
        observations = [
            Observation(
                observation_type=kind,
                value=value,
                analyzer_id=self.analyzer_id,
                source="verified-ingestion",
                observed_at=started,
                confidence="exact",
            )
            for kind, value in values.items()
        ]
        completed = datetime.now(UTC)
        return AnalyzerResult(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="avbox.analyzers.generic.IdentityAnalyzer",
            product_version="1",
            qualification_state=QualificationState.QUALIFIED,
            started_at=started,
            completed_at=completed,
            duration_seconds=(completed - started).total_seconds(),
            execution_profile="avbox-built-in-read-only",
            native_status="exact",
            observations=observations,
        )


class MetadataAnalyzer(GenericAnalyzer):
    analyzer_id = "basic-metadata"
    analyzer_class = ScannerClass.METADATA_ANALYZER
    product = "AVBox Basic Metadata"

    def probe(self) -> ProbeResult:
        return ProbeResult(True, "built-in bounded metadata", QualificationState.PROBED, "1")

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        del source, job_id
        started = datetime.now(UTC)
        original = artifact.submitted_filename or artifact.filename
        basename = PurePath(original.replace("\\", "/")).name
        suffixes = [value.removeprefix(".").lower() for value in PurePath(basename).suffixes]
        primary = suffixes[-1] if suffixes else None
        compound = ".".join(suffixes[-2:]) if len(suffixes) >= 2 else None
        recognized_compound = compound if compound in COMPOUND_EXTENSIONS else None
        observations = [
            _observation(self.analyzer_id, "filename.original", original, started),
            _observation(self.analyzer_id, "filename.basename", basename, started),
            _observation(self.analyzer_id, "filename.length", len(original), started),
            _observation(self.analyzer_id, "filename.extensions", suffixes, started),
            _observation(self.analyzer_id, "filename.extension", primary, started),
            _observation(
                self.analyzer_id, "filename.compound_extension", recognized_compound, started
            ),
            _observation(
                self.analyzer_id, "object.declared_media_type", artifact.media_type, started
            ),
        ]
        assessments: list[Assessment] = []
        if len(suffixes) > 1 and recognized_compound is None:
            assessments.append(
                Assessment(
                    assessment_type="MULTIPLE_EXTENSION",
                    analyzer_id=self.analyzer_id,
                    statement="filename has multiple non-compound suffix components",
                    confidence=Confidence.HIGH,
                    evidence_refs=["filename.extensions"],
                )
            )
        completed = datetime.now(UTC)
        return AnalyzerResult(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="avbox.analyzers.generic.MetadataAnalyzer",
            product_version="1",
            qualification_state=QualificationState.QUALIFIED,
            started_at=started,
            completed_at=completed,
            duration_seconds=(completed - started).total_seconds(),
            execution_profile="avbox-built-in-read-only",
            native_status="complete",
            observations=observations,
            assessments=assessments,
        )


class FileMagicAnalyzer(GenericAnalyzer):
    analyzer_id = "file-type"
    analyzer_class = ScannerClass.FILE_TYPE_ANALYZER
    product = "file/libmagic"

    def __init__(self, settings: AppSettings):
        self.raw_output_root = settings.paths.raw_output
        self.runner = IsolatedCommandRunner(
            timeout=settings.runtime.default_timeout_seconds,
            memory_mib=settings.runtime.memory_limit_mib,
            use_bwrap=settings.runtime.use_bubblewrap,
        )

    def probe(self) -> ProbeResult:
        try:
            result = self.runner.run(["file", "--version"], cwd=Path("/tmp"))
        except OSError as exc:
            return ProbeResult(False, str(exc), QualificationState.NOT_INSTALLED)
        text = (result.stdout or result.stderr).strip()
        return ProbeResult(
            result.exit_code == 0 and not result.isolation_failed,
            text or "file probe failed",
            QualificationState.PROBED if result.exit_code == 0 else QualificationState.DEGRADED,
            text.splitlines()[0] if text else None,
            {"magic_database": text.splitlines()[1] if len(text.splitlines()) > 1 else None},
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        started_dt = datetime.now(UTC)
        started = time.monotonic()
        modes = {
            "description": ["file", "--brief", "--no-pad", "--", str(source)],
            "mime_type": ["file", "--brief", "--mime-type", "--", str(source)],
            "encoding": ["file", "--brief", "--mime-encoding", "--", str(source)],
        }
        try:
            results = {
                name: self.runner.run(argv, cwd=source.parent) for name, argv in modes.items()
            }
        except OSError as exc:
            completed = datetime.now(UTC)
            return AnalyzerResult(
                analyzer_id=self.analyzer_id,
                analyzer_class=self.analyzer_class,
                product=self.product,
                implementation="Debian file CLI",
                qualification_state=QualificationState.NOT_INSTALLED,
                started_at=started_dt,
                completed_at=completed,
                duration_seconds=time.monotonic() - started,
                execution_profile="linux-bounded-unavailable",
                native_status="error",
                errors=[f"analyzer-unavailable: {exc}"],
            )
        combined = CommandResult(
            argv=("file", "M1.2-modes"),
            exit_code=max(value.exit_code for value in results.values()),
            stdout="".join(f"{name}: {value.stdout.strip()}\n" for name, value in results.items()),
            stderr="".join(value.stderr for value in results.values()),
            duration_seconds=time.monotonic() - started,
            timed_out=any(value.timed_out for value in results.values()),
            isolated=all(value.isolated for value in results.values()),
            isolation_failed=any(value.isolation_failed for value in results.values()),
        )
        reference = store_raw_output(self.raw_output_root, job_id, self.analyzer_id, combined)
        probe = self.probe()
        errors: list[str] = []
        if combined.isolation_failed:
            errors.append("isolation-failed")
        elif combined.timed_out:
            errors.append("analyzer-timeout")
        elif combined.exit_code != 0:
            errors.append("file-command-failed")
        description = results["description"].stdout.strip() or None
        mime_type = results["mime_type"].stdout.strip() or None
        encoding = results["encoding"].stdout.strip() or None
        if not errors and (description is None or mime_type is None or encoding is None):
            errors.append("malformed-output")
        observations = (
            []
            if errors
            else [
                _observation(
                    self.analyzer_id,
                    "file.magic.description",
                    description,
                    started_dt,
                    reference,
                ),
                _observation(
                    self.analyzer_id, "file.mime.type", mime_type, started_dt, reference
                ),
                _observation(
                    self.analyzer_id, "file.mime.encoding", encoding, started_dt, reference
                ),
            ]
        )
        assessments = [] if errors else self._assess(artifact, description, mime_type, encoding)
        completed = datetime.now(UTC)
        raw_bytes = (
            combined.stdout
            + ("\n[stderr]\n" + combined.stderr if combined.stderr else "")
        ).encode()
        return AnalyzerResult(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="Debian file CLI backed by libmagic",
            product_version=probe.version,
            engine_version=probe.version,
            definition_state=probe.definition_state or {},
            qualification_state=(
                QualificationState.DEGRADED if errors else QualificationState.QUALIFIED
            ),
            started_at=started_dt,
            completed_at=completed,
            duration_seconds=combined.duration_seconds,
            execution_profile=(
                "linux-bwrap-read-only-no-network"
                if combined.isolated
                else "linux-bounded-direct-degraded"
            ),
            native_status="error" if errors else "complete",
            native_exit_code=combined.exit_code,
            observations=observations,
            assessments=assessments,
            raw_output=RawOutputDescriptor(
                raw_output_id=reference,
                sha256=hashlib.sha256(raw_bytes).hexdigest(),
                size=len(raw_bytes),
            ),
            errors=errors,
        )

    def _assess(
        self,
        artifact: InputArtifact,
        description: str | None,
        mime_type: str | None,
        encoding: str | None,
    ) -> list[Assessment]:
        family, file_format, platform, architecture, confidence = _type_from_magic(
            artifact.byte_size, description or "", mime_type or ""
        )
        values = [
            Assessment(
                assessment_type="FILE_TYPE",
                analyzer_id=self.analyzer_id,
                statement=f"family={family}; format={file_format or 'UNKNOWN'}",
                confidence=confidence,
                evidence_refs=["file.magic.description", "file.mime.type"],
            )
        ]
        if platform:
            values.append(
                Assessment(
                    assessment_type="PLATFORM_HINT",
                    analyzer_id=self.analyzer_id,
                    statement=platform,
                    confidence=Confidence.HIGH,
                    evidence_refs=["file.magic.description"],
                )
            )
        if architecture:
            values.append(
                Assessment(
                    assessment_type="ARCHITECTURE_HINT",
                    analyzer_id=self.analyzer_id,
                    statement=architecture,
                    confidence=Confidence.HIGH,
                    evidence_refs=["file.magic.description"],
                )
            )
        original = artifact.submitted_filename or artifact.filename
        suffixes = [value.removeprefix(".").lower() for value in PurePath(original).suffixes]
        expected = EXTENSION_FAMILIES.get(suffixes[-1]) if suffixes else None
        if expected and family not in {"unknown", expected}:
            values.append(
                Assessment(
                    assessment_type="EXTENSION_TYPE_MISMATCH",
                    analyzer_id=self.analyzer_id,
                    statement=f"extension suggests {expected}, libmagic indicates {family}",
                    confidence=Confidence.HIGH,
                    evidence_refs=["filename.extension", "file.mime.type"],
                )
            )
            values.append(
                Assessment(
                    assessment_type="EXTENSION_MIME_MISMATCH",
                    analyzer_id=self.analyzer_id,
                    statement=f"extension suggests {expected}, libmagic MIME is {mime_type}",
                    confidence=Confidence.HIGH,
                    evidence_refs=["filename.extension", "file.mime.type"],
                )
            )
        declared = artifact.media_type.lower()
        if declared not in {"", "application/octet-stream"} and mime_type and declared != mime_type:
            values.append(
                Assessment(
                    assessment_type="DECLARED_MEDIA_TYPE_MISMATCH",
                    analyzer_id=self.analyzer_id,
                    statement=f"declared {declared}, libmagic reports {mime_type}",
                    confidence=Confidence.HIGH,
                    evidence_refs=["object.declared_media_type", "file.mime.type"],
                )
            )
        binary_text = (
            "text"
            if mime_type == "text/plain" or encoding not in {None, "binary"}
            else "binary"
        )
        values.append(
            Assessment(
                assessment_type="BINARY_TEXT_CLASS",
                analyzer_id=self.analyzer_id,
                statement=binary_text,
                confidence=Confidence.HIGH,
                evidence_refs=["file.mime.type", "file.mime.encoding"],
            )
        )
        return values


def _observation(
    analyzer: str, kind: str, value: object, timestamp: datetime, evidence: str | None = None
) -> Observation:
    return Observation(
        observation_type=kind,
        value=value,
        analyzer_id=analyzer,
        evidence_refs=[evidence] if evidence else [],
        source="analyzer",
        observed_at=timestamp,
    )


def _type_from_magic(
    size: int, description: str, mime_type: str
) -> tuple[str, str | None, str | None, str | None, Confidence]:
    lower = description.lower()
    if size == 0 or "empty" in lower or mime_type == "inode/x-empty":
        return "empty", "EMPTY", None, None, Confidence.HIGH
    if mime_type.startswith("text/"):
        return "text", "TEXT", None, None, Confidence.HIGH
    if mime_type.startswith("image/"):
        return "image", mime_type.split("/", 1)[1].upper(), None, None, Confidence.HIGH
    container_markers = ("zip archive", "gzip compressed", "tar archive", "iso 9660")
    if any(value in lower for value in container_markers):
        return "container", mime_type, None, None, Confidence.HIGH
    platform = None
    file_format = None
    if "pe32" in lower:
        platform, file_format = "windows", "PE"
    elif "elf " in lower:
        platform, file_format = "linux/unix", "ELF"
    elif "mach-o" in lower:
        platform, file_format = "macos", "MACH-O"
    elif "dos executable" in lower or "ms-dos executable" in lower:
        platform, file_format = "dos", "DOS-MZ"
    architectures = (("x86-64", "x86-64"), ("80386", "x86"), ("arm", "ARM"), ("m68k", "m68k"))
    architecture = next((value for token, value in architectures if token in lower), None)
    if file_format:
        return "executable", file_format, platform, architecture, Confidence.HIGH
    return "unknown", None, None, architecture, Confidence.UNKNOWN


def build_generic_analyzers(settings: AppSettings) -> dict[str, GenericAnalyzer]:
    values: list[GenericAnalyzer] = [
        IdentityAnalyzer(),
        MetadataAnalyzer(),
        FileMagicAnalyzer(settings),
    ]
    return {value.analyzer_id: value for value in values}
