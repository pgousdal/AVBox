from __future__ import annotations

import hashlib
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

from avbox.models import (
    Capability,
    FindingKind,
    QualificationState,
    ScannerClass,
    ScannerResult,
    Verdict,
)

from .base import PreparedScan, ProbeResult, ScannerAdapter, SystemDetectorAdapter
from .command import CommandResult, IsolatedCommandRunner, store_raw_output


class CommandFileAdapter(ScannerAdapter):
    executable = ""
    scanner_class = ScannerClass.ANTIVIRUS_ENGINE

    def __init__(
        self,
        *,
        raw_output_root: Path,
        timeout: int,
        rules: Path | None = None,
        memory_mib: int = 1024,
        use_bwrap: bool = True,
    ):
        self.raw_output_root = raw_output_root
        self.runner = IsolatedCommandRunner(
            timeout=timeout, memory_mib=memory_mib, use_bwrap=use_bwrap
        )
        self.rules = rules

    @property
    def scanner_id(self) -> str:
        return self.__class__.__name__.removesuffix("Adapter").lower()

    def capabilities(self) -> set[Capability]:
        return {Capability.FILE_SCAN, Capability.SCAN_ONLY}

    def version_args(self) -> list[str]:
        return [self.executable, "--version"]

    def definition_state(self) -> dict[str, str | int | None]:
        return {}

    def probe(self) -> ProbeResult:
        path = shutil.which(self.executable)
        if not path:
            return ProbeResult(False, f"{self.executable} not found")
        result = self.runner.run(self.version_args(), cwd=Path("/tmp"))
        version = (
            (result.stdout or result.stderr).strip().splitlines()[0]
            if not result.timed_out
            else None
        )
        state = QualificationState.PROBED if result.exit_code == 0 else QualificationState.DEGRADED
        return ProbeResult(True, path, state, version, self.definition_state())

    def prepare(self, *, job_id: str, immutable_input: Path, working_root: Path) -> PreparedScan:
        if not immutable_input.is_file():
            raise ValueError("ordinary regular files only")
        job_root = working_root / job_id / self.scanner_id
        job_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        staged = job_root / "object"
        shutil.copyfile(immutable_input, staged)
        staged.chmod(0o400)
        return PreparedScan(job_id, immutable_input, staged, {})

    def command(self, path: Path) -> list[str]:
        raise NotImplementedError

    def scan(self, prepared: PreparedScan) -> CommandResult:
        return self.runner.run(
            self.command(prepared.working_path),
            cwd=prepared.working_path.parent,
            read_only_input=prepared.working_path,
        )

    def cleanup(self, prepared: PreparedScan) -> None:
        prepared.working_path.chmod(0o600)
        prepared.working_path.unlink(missing_ok=True)
        prepared.working_path.parent.rmdir()

    def result(
        self,
        native: CommandResult,
        verdict: Verdict,
        native_verdict: str,
        detection: str | None,
        kind: FindingKind | None,
    ) -> ScannerResult:
        ref = store_raw_output(
            self.raw_output_root,
            "system" if not native.argv else self._job_id(native),
            self.scanner_id,
            native,
        )
        probe = self.probe()
        return ScannerResult(
            scanner_id=self.scanner_id,
            native_verdict=native_verdict,
            normalized_verdict=verdict,
            detection_name=detection,
            exit_code=native.exit_code,
            raw_output_ref=ref,
            engine_version=probe.version,
            definition_version=self.result_definition_version(),
            runtime_profile=(
                "linux-bwrap-read-only-no-network"
                if native.isolated
                else "linux-bounded-direct-degraded"
            ),
            scanned_at=datetime.now(UTC),
            finding_kind=kind,
            definition_state=self.definition_state(),
            duration_seconds=native.duration_seconds,
        )

    def result_definition_version(self) -> str | None:
        return None

    def _job_id(self, native: CommandResult) -> str:
        del native
        return getattr(self, "_active_job_id", "unknown")

    def run_prepared(self, prepared: PreparedScan) -> tuple[Verdict, ScannerResult]:
        self._active_job_id = prepared.job_id
        return self.normalize(self.scan(prepared))


class ClamAVAdapter(CommandFileAdapter):
    executable = "clamscan"

    def command(self, path: Path) -> list[str]:
        return [self.executable, "--no-summary", "--infected", "--", str(path)]

    def definition_state(self) -> dict[str, str | int | None]:
        state: dict[str, str | int | None] = {}
        for root in (Path("/var/lib/clamav"),):
            for name in ("main", "daily", "bytecode"):
                for suffix in ("cld", "cvd"):
                    path = root / f"{name}.{suffix}"
                    if path.is_file():
                        state[f"{name}_file"] = path.name
                        state[f"{name}_mtime"] = int(path.stat().st_mtime)
                        header = path.open("rb").read(512).rstrip(b"\0").decode(errors="replace")
                        fields = header.split(":")
                        if len(fields) >= 4 and fields[0] == "ClamAV-VDB":
                            state[f"{name}_build_time"] = fields[1]
                            state[f"{name}_version"] = fields[2]
                            state[f"{name}_signatures"] = fields[3]
        return state

    def result_definition_version(self) -> str | None:
        value = self.definition_state().get("daily_version")
        return str(value) if value is not None else None

    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]:
        native = _command(native_result)
        if native.timed_out:
            return Verdict.ERROR, self.result(
                native, Verdict.ERROR, "timeout", None, FindingKind.OPERATIONAL_ERROR
            )
        if native.exit_code == 0:
            return Verdict.CLEAN, self.result(native, Verdict.CLEAN, "clean", None, None)
        if native.exit_code == 1:
            line = next(
                (line for line in native.stdout.splitlines() if line.endswith(" FOUND")), ""
            )
            detection = line.rsplit(": ", 1)[-1].removesuffix(" FOUND") or None
            return Verdict.MALICIOUS, self.result(
                native, Verdict.MALICIOUS, "FOUND", detection, FindingKind.SIGNATURE_MATCH
            )
        return Verdict.ERROR, self.result(
            native, Verdict.ERROR, "scanner-error", None, FindingKind.OPERATIONAL_ERROR
        )

    def update(self) -> CommandResult:
        return IsolatedCommandRunner(timeout=600, use_bwrap=False).run(
            ["freshclam"], cwd=Path("/tmp")
        )


class YaraAdapter(CommandFileAdapter):
    executable = "yara"
    scanner_class = ScannerClass.RULE_ENGINE

    @property
    def scanner_id(self) -> str:
        return "yara"

    def command(self, path: Path) -> list[str]:
        if not self.rules:
            raise ValueError("YARA rules path is not configured")
        return [self.executable, "--no-warnings", str(self.rules), str(path)]

    def definition_state(self) -> dict[str, str | int | None]:
        if not self.rules or not self.rules.is_file():
            return {"rule_set": None}
        return {
            "rule_set": self.rules.name,
            "rule_set_sha256": hashlib.sha256(self.rules.read_bytes()).hexdigest(),
        }

    def result_definition_version(self) -> str | None:
        value = self.definition_state().get("rule_set_sha256")
        return str(value) if value is not None else None

    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]:
        native = _command(native_result)
        if native.timed_out or native.exit_code not in {0, 1}:
            return Verdict.ERROR, self.result(
                native, Verdict.ERROR, "scanner-error", None, FindingKind.OPERATIONAL_ERROR
            )
        matches = [line.split(maxsplit=1)[0] for line in native.stdout.splitlines() if line.strip()]
        if matches:
            return Verdict.SUSPICIOUS, self.result(
                native, Verdict.SUSPICIOUS, "rule-match", ",".join(matches), FindingKind.RULE_MATCH
            )
        return Verdict.CLEAN, self.result(native, Verdict.CLEAN, "no-match", None, None)


class YaraXAdapter(YaraAdapter):
    executable = "yr"

    @property
    def scanner_id(self) -> str:
        return "yara-x"

    def command(self, path: Path) -> list[str]:
        if not self.rules:
            raise ValueError("YARA-X rules path is not configured")
        return [self.executable, "scan", str(self.rules), str(path)]


class LokiAdapter(CommandFileAdapter):
    # Debian's unrelated package named "loki" must never satisfy this probe.
    executable = "loki.py"
    scanner_class = ScannerClass.IOC_DETECTOR

    def command(self, path: Path) -> list[str]:
        return [self.executable, "--path", str(path), "--noprocscan", "--dontwait", "--noindicator"]

    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]:
        native = _command(native_result)
        text = native.stdout + native.stderr
        if native.timed_out or native.exit_code not in {0, 1}:
            return Verdict.ERROR, self.result(
                native, Verdict.ERROR, "scanner-error", None, FindingKind.OPERATIONAL_ERROR
            )
        if re.search(r"\bALERT\b", text, re.I):
            return Verdict.MALICIOUS, self.result(
                native, Verdict.MALICIOUS, "ALERT", None, FindingKind.IOC_MATCH
            )
        if re.search(r"\bWARNING\b", text, re.I):
            return Verdict.SUSPICIOUS, self.result(
                native, Verdict.SUSPICIOUS, "WARNING", None, FindingKind.HEURISTIC_WARNING
            )
        return Verdict.CLEAN, self.result(native, Verdict.CLEAN, "clean", None, None)


class MaldetAdapter(CommandFileAdapter):
    executable = "maldet"
    scanner_class = ScannerClass.MALWARE_DETECTOR

    def command(self, path: Path) -> list[str]:
        return [self.executable, "--scan-all", str(path)]

    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]:
        native = _command(native_result)
        text = native.stdout + native.stderr
        if native.timed_out or native.exit_code not in {0, 1}:
            return Verdict.ERROR, self.result(
                native, Verdict.ERROR, "scanner-error", None, FindingKind.OPERATIONAL_ERROR
            )
        match = re.search(r"hits\s*:\s*([1-9]\d*)", text, re.I)
        if match:
            return Verdict.MALICIOUS, self.result(
                native, Verdict.MALICIOUS, "hits", match.group(1), FindingKind.SIGNATURE_MATCH
            )
        return Verdict.CLEAN, self.result(native, Verdict.CLEAN, "no-hits", None, None)


class RootkitAdapter(SystemDetectorAdapter):
    scanner_class = ScannerClass.SYSTEM_DETECTOR

    def __init__(
        self,
        scanner_id: str,
        executable: str,
        raw_output_root: Path,
        timeout: int,
        memory_mib: int = 1024,
    ):
        self._scanner_id = scanner_id
        self.executable = executable
        self.raw_output_root = raw_output_root
        self.runner = IsolatedCommandRunner(timeout=timeout, memory_mib=memory_mib, use_bwrap=False)

    @property
    def scanner_id(self) -> str:
        return self._scanner_id

    def probe(self) -> ProbeResult:
        path = shutil.which(self.executable)
        if not path:
            return ProbeResult(False, f"{self.executable} not found")
        args = (
            [self.executable, "--version"]
            if self.scanner_id == "rkhunter"
            else [self.executable, "-V"]
        )
        result = self.runner.run(args, cwd=Path("/tmp"))
        text = (result.stdout or result.stderr).strip().splitlines()
        return ProbeResult(
            True, path, QualificationState.PROBED, text[0] if text else "unknown", {}
        )

    def system_scan(self) -> CommandResult:
        args = (
            [self.executable, "--check", "--skip-keypress", "--report-warnings-only", "--nocolors"]
            if self.scanner_id == "rkhunter"
            else [self.executable, "-q"]
        )
        return self.runner.run(args, cwd=Path("/tmp"))

    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]:
        native = _command(native_result)
        text = native.stdout + native.stderr
        ref = store_raw_output(self.raw_output_root, "system", self.scanner_id, native)
        error = native.timed_out or native.exit_code not in {0, 1}
        warning = bool(text.strip()) or native.exit_code == 1
        verdict = Verdict.ERROR if error else Verdict.SUSPICIOUS if warning else Verdict.CLEAN
        kind = (
            FindingKind.OPERATIONAL_ERROR
            if error
            else FindingKind.ROOTKIT_WARNING
            if warning
            else None
        )
        result = ScannerResult(
            scanner_id=self.scanner_id,
            native_verdict="error" if error else "warning" if warning else "clean",
            normalized_verdict=verdict,
            raw_output_ref=ref,
            exit_code=native.exit_code,
            runtime_profile="linux-system-detector",
            scanned_at=datetime.now(UTC),
            finding_kind=kind,
            duration_seconds=native.duration_seconds,
        )
        return verdict, result

    def update(self) -> CommandResult:
        if self.scanner_id != "rkhunter":
            raise NotImplementedError("chkrootkit has no separate property update operation")
        return self.runner.run([self.executable, "--update"], cwd=Path("/tmp"))


def _command(value: object) -> CommandResult:
    if not isinstance(value, CommandResult):
        raise TypeError("adapter expected CommandResult")
    return value
