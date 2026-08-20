from __future__ import annotations

import json
import math
import re
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

from avbox.analyzers.generic import GenericAnalyzer, _observation
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
from avbox.scanners.command import IsolatedCommandRunner, store_raw_output

PRINTABLE = set(range(0x20, 0x7F))
STRING_RE = re.compile(r"[\x20-\x7e]{2,}")


def _result(
    *,
    analyzer_id: str,
    analyzer_class: ScannerClass,
    product: str,
    implementation: str,
    started: datetime,
    monotonic_start: float,
    status: str,
    state: QualificationState,
    observations: list[Observation] | None = None,
    assessments: list[Assessment] | None = None,
    errors: list[str] | None = None,
    raw: RawOutputDescriptor | None = None,
    version: str | None = "1",
) -> AnalyzerResult:
    completed = datetime.now(UTC)
    return AnalyzerResult(
        analyzer_id=analyzer_id,
        analyzer_class=analyzer_class,
        product=product,
        implementation=implementation,
        product_version=version,
        qualification_state=state,
        started_at=started,
        completed_at=completed,
        duration_seconds=time.monotonic() - monotonic_start,
        execution_profile="avbox-built-in-read-only"
        if analyzer_id != "generic-metadata"
        else "linux-bwrap-read-only-no-network",
        native_status=status,
        observations=observations or [],
        assessments=assessments or [],
        errors=errors or [],
        raw_output=raw,
    )


class StringsAnalyzer(GenericAnalyzer):
    analyzer_id = "strings"
    analyzer_class = ScannerClass.STRINGS_ANALYZER
    product = "AVBox bounded strings"

    def __init__(self, settings: AppSettings):
        self.minimum = settings.runtime.strings_min_length
        self.maximum = settings.runtime.strings_max_length
        self.maximum_count = settings.runtime.strings_max_count
        self.maximum_total = settings.runtime.strings_max_total_chars
        self.maximum_source = settings.runtime.strings_max_source_bytes

    def probe(self) -> ProbeResult:
        return ProbeResult(True, "built-in bounded strings", QualificationState.PROBED, "1")

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        del job_id
        started = datetime.now(UTC)
        tick = time.monotonic()
        try:
            with source.open("rb") as stream:
                data = stream.read(self.maximum_source + 1)
        except OSError as exc:
            return _result(
                analyzer_id=self.analyzer_id,
                analyzer_class=self.analyzer_class,
                product=self.product,
                implementation="avbox bounded internal extractor",
                started=started,
                monotonic_start=tick,
                status="error",
                state=QualificationState.DEGRADED,
                errors=[f"read-error: {exc}"],
            )
        source_truncated = len(data) > self.maximum_source
        data = data[: self.maximum_source]
        values: list[dict[str, str]] = []
        observed = 0
        for encoding, decoded in self._decoded_views(data):
            for match in STRING_RE.finditer(decoded):
                value = match.group(0)
                if len(value) > self.maximum:
                    value = value[: self.maximum]
                    source_truncated = True
                observed += 1
                if len(values) >= self.maximum_count:
                    source_truncated = True
                    continue
                if sum(len(item["value"]) for item in values) + len(value) > self.maximum_total:
                    source_truncated = True
                    continue
                values.append({"encoding": encoding, "value": value})
        observations = [
            _observation(self.analyzer_id, "strings.count_observed", observed, started),
            _observation(self.analyzer_id, "strings.count_returned", len(values), started),
            _observation(self.analyzer_id, "strings.truncated", source_truncated, started),
        ]
        observations.extend(
            observation
            for item in values
            for observation in (
                _observation(self.analyzer_id, "strings.encoding", item["encoding"], started),
                _observation(self.analyzer_id, "strings.value", item, started),
            )
        )
        return _result(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="avbox bounded internal extractor",
            started=started,
            monotonic_start=tick,
            status="complete",
            state=QualificationState.QUALIFIED,
            observations=observations,
            assessments=(
                [
                    Assessment(
                        assessment_type="STRING_OUTPUT_TRUNCATED",
                        analyzer_id=self.analyzer_id,
                        statement="bounded string output or source scan was truncated",
                        confidence=Confidence.HIGH,
                        evidence_refs=["strings.truncated"],
                    )
                ]
                if source_truncated
                else []
            ),
        )

    def _decoded_views(self, data: bytes) -> list[tuple[str, str]]:
        views: list[tuple[str, str]] = []
        views.append(
            (
                "ASCII",
                bytes(value if value in PRINTABLE else 0x00 for value in data).decode(
                    "ascii", errors="ignore"
                ),
            )
        )
        views.append(("UTF-8", data.decode("utf-8", errors="ignore")))
        for name, codec in (("UTF-16LE", "utf-16le"), ("UTF-16BE", "utf-16be")):
            for offset in (0, 1):
                aligned = data[offset : offset + len(data[offset:]) - (len(data[offset:]) % 2)]
                views.append((name, aligned.decode(codec, errors="ignore")))
        return views


class ByteStatisticsAnalyzer(GenericAnalyzer):
    analyzer_id = "byte-statistics"
    analyzer_class = ScannerClass.BYTE_STATISTICS_ANALYZER
    product = "AVBox byte statistics"

    def probe(self) -> ProbeResult:
        return ProbeResult(
            True, "built-in streaming byte statistics", QualificationState.PROBED, "1"
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        del artifact, job_id
        started = datetime.now(UTC)
        tick = time.monotonic()
        histogram = [0] * 256
        total = 0
        try:
            with source.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    total += len(chunk)
                    for value in chunk:
                        histogram[value] += 1
        except OSError as exc:
            return _result(
                analyzer_id=self.analyzer_id,
                analyzer_class=self.analyzer_class,
                product=self.product,
                implementation="avbox streaming histogram and Shannon entropy",
                started=started,
                monotonic_start=tick,
                status="error",
                state=QualificationState.DEGRADED,
                errors=[f"read-error: {exc}"],
            )
        entropy = 0.0
        if total:
            entropy = -sum(
                (count / total) * math.log2(count / total) for count in histogram if count
            )
        observations = [
            _observation(self.analyzer_id, "byte.entropy.shannon", round(entropy, 8), started),
            _observation(
                self.analyzer_id, "byte.unique_count", sum(bool(x) for x in histogram), started
            ),
            _observation(
                self.analyzer_id,
                "byte.nul_fraction",
                histogram[0] / total if total else 0.0,
                started,
            ),
            _observation(
                self.analyzer_id,
                "byte.printable_fraction",
                sum(histogram[value] for value in PRINTABLE) / total if total else 0.0,
                started,
            ),
        ]
        return _result(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="avbox streaming histogram and Shannon entropy",
            started=started,
            monotonic_start=tick,
            status="complete",
            state=QualificationState.QUALIFIED,
            observations=observations,
        )


class ExifToolAnalyzer(GenericAnalyzer):
    analyzer_id = "generic-metadata"
    analyzer_class = ScannerClass.METADATA_ANALYZER
    product = "ExifTool"

    def __init__(self, settings: AppSettings):
        self.maximum_fields = settings.runtime.metadata_max_fields
        self.maximum_value = settings.runtime.metadata_max_value_length
        self.maximum_total = settings.runtime.metadata_max_total_chars
        self.raw_output_root = settings.paths.raw_output
        self.runner = IsolatedCommandRunner(
            timeout=settings.runtime.default_timeout_seconds,
            memory_mib=settings.runtime.memory_limit_mib,
            use_bwrap=settings.runtime.use_bubblewrap,
        )

    def probe(self) -> ProbeResult:
        if not shutil.which("exiftool"):
            return ProbeResult(False, "exiftool not installed", QualificationState.NOT_INSTALLED)
        result = self.runner.run(["exiftool", "-ver"], cwd=Path("/tmp"))
        version = result.stdout.strip() or result.stderr.strip()
        return ProbeResult(
            result.exit_code == 0 and not result.isolation_failed,
            version or "exiftool probe failed",
            QualificationState.PROBED if result.exit_code == 0 else QualificationState.DEGRADED,
            version or None,
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        started = datetime.now(UTC)
        tick = time.monotonic()
        try:
            result = self.runner.run(
                ["exiftool", "-j", "-G1", "-s", "-q", "-q", "--", str(source)], cwd=source.parent
            )
        except OSError as exc:
            return _result(
                analyzer_id=self.analyzer_id,
                analyzer_class=self.analyzer_class,
                product=self.product,
                implementation="Debian ExifTool JSON mode",
                started=started,
                monotonic_start=tick,
                status="unavailable",
                state=QualificationState.NOT_INSTALLED,
                errors=[str(exc)],
            )
        payload = (
            result.stdout + ("\n[stderr]\n" + result.stderr if result.stderr else "")
        ).encode()
        reference = store_raw_output(self.raw_output_root, job_id, self.analyzer_id, result)
        raw = RawOutputDescriptor(
            raw_output_id=reference,
            sha256=__import__("hashlib").sha256(payload).hexdigest(),
            size=len(payload),
        )
        errors: list[str] = []
        status = "complete"
        state = QualificationState.QUALIFIED
        if result.timed_out:
            errors.append("analyzer-timeout")
            status = "timeout"
            state = QualificationState.DEGRADED
        elif result.isolation_failed:
            errors.append("isolation-failed")
            status = "error"
            state = QualificationState.DEGRADED
        observations: list[Observation] = []
        truncated = False
        if not errors:
            try:
                documents = json.loads(result.stdout)
                document = documents[0] if isinstance(documents, list) and documents else {}
                total = 0
                for index, (key, value) in enumerate(document.items()):
                    if index >= self.maximum_fields:
                        truncated = True
                        break
                    if key in {"SourceFile", "System:Directory"}:
                        if key == "SourceFile":
                            value = Path(str(value)).name
                        else:
                            continue
                    text = str(value)
                    if len(text) > self.maximum_value:
                        text = text[: self.maximum_value]
                        truncated = True
                    if total + len(text) > self.maximum_total:
                        truncated = True
                        break
                    total += len(text)
                    safe_key = re.sub(r"[^A-Za-z0-9_.-]", "_", str(key))
                    observations.append(
                        _observation(
                            self.analyzer_id,
                            f"metadata.exiftool.{safe_key}",
                            {"tag": key, "value": text},
                            started,
                            reference,
                        )
                    )
            except (ValueError, TypeError, IndexError) as exc:
                errors.append(f"malformed-output: {exc}")
                status = "error"
                state = QualificationState.DEGRADED
        if result.exit_code != 0 and not errors:
            status = "not-applicable"
        observations.append(
            _observation(self.analyzer_id, "metadata.truncated", truncated, started, reference)
        )
        return _result(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="Debian ExifTool JSON mode",
            started=started,
            monotonic_start=tick,
            status=status,
            state=state,
            observations=observations,
            errors=errors,
            raw=raw,
            version=self.probe().version,
        )


class SSDeepAnalyzer(GenericAnalyzer):
    analyzer_id = "similarity"
    analyzer_class = ScannerClass.SIMILARITY_ANALYZER
    product = "ssdeep"

    def __init__(self, settings: AppSettings):
        self.raw_output_root = settings.paths.raw_output
        self.runner = IsolatedCommandRunner(
            timeout=settings.runtime.default_timeout_seconds,
            memory_mib=settings.runtime.memory_limit_mib,
            use_bwrap=settings.runtime.use_bubblewrap,
        )

    def probe(self) -> ProbeResult:
        if not shutil.which("ssdeep"):
            return ProbeResult(False, "ssdeep not installed", QualificationState.NOT_INSTALLED)
        result = self.runner.run(["ssdeep", "-V"], cwd=Path("/tmp"))
        text = (result.stdout or result.stderr).strip()
        return ProbeResult(
            result.exit_code == 0 and not result.isolation_failed,
            text or "ssdeep probe failed",
            QualificationState.PROBED if result.exit_code == 0 else QualificationState.DEGRADED,
            text or None,
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        started = datetime.now(UTC)
        tick = time.monotonic()
        try:
            result = self.runner.run(["ssdeep", "-b", "--", str(source)], cwd=source.parent)
        except OSError as exc:
            return _result(
                analyzer_id=self.analyzer_id,
                analyzer_class=self.analyzer_class,
                product=self.product,
                implementation="Debian ssdeep CLI",
                started=started,
                monotonic_start=tick,
                status="unavailable",
                state=QualificationState.NOT_INSTALLED,
                errors=[str(exc)],
            )
        payload = (
            result.stdout + ("\n[stderr]\n" + result.stderr if result.stderr else "")
        ).encode()
        reference = store_raw_output(self.raw_output_root, job_id, self.analyzer_id, result)
        raw = RawOutputDescriptor(
            raw_output_id=reference,
            sha256=__import__("hashlib").sha256(payload).hexdigest(),
            size=len(payload),
        )
        errors: list[str] = []
        line = next(
            (
                item
                for item in result.stdout.splitlines()
                if item and not item.startswith("ssdeep,")
            ),
            "",
        )
        fingerprint = line.rsplit(",", 1)[0] if "," in line else ""
        if result.timed_out:
            errors.append("analyzer-timeout")
        elif result.isolation_failed:
            errors.append("isolation-failed")
        elif result.exit_code != 0:
            errors.append("ssdeep-failed")
        if not fingerprint and not errors:
            return _result(
                analyzer_id=self.analyzer_id,
                analyzer_class=self.analyzer_class,
                product=self.product,
                implementation="Debian ssdeep CLI",
                started=started,
                monotonic_start=tick,
                status="not-applicable",
                state=QualificationState.QUALIFIED,
                errors=["fingerprint-unavailable: object too small or low variation"],
                raw=raw,
                version=self.probe().version,
            )
        observations = (
            [
                _observation(
                    self.analyzer_id,
                    "similarity.ssdeep",
                    {
                        "algorithm": "ssdeep",
                        "fingerprint": fingerprint,
                        "source_sha256": artifact.hashes.sha256,
                    },
                    started,
                    reference,
                )
            ]
            if fingerprint
            else []
        )
        return _result(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="Debian ssdeep CLI",
            started=started,
            monotonic_start=tick,
            status="error" if errors else "complete",
            state=QualificationState.DEGRADED if errors else QualificationState.QUALIFIED,
            observations=observations,
            errors=errors,
            raw=raw,
            version=self.probe().version,
        )


def build_static_analyzers(settings: AppSettings) -> dict[str, GenericAnalyzer]:
    return {
        "strings": StringsAnalyzer(settings),
        "byte-statistics": ByteStatisticsAnalyzer(),
        "generic-metadata": ExifToolAnalyzer(settings),
        "similarity": SSDeepAnalyzer(settings),
    }
