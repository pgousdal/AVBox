from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from avbox.application import JobService, ScanService, aggregate_verdict
from avbox.models import Capability, FindingKind, ScannerClass, ScannerResult, Verdict
from avbox.preservation import PreservationService
from avbox.scanners.adapters import (
    ClamAVAdapter,
    LokiAdapter,
    MaldetAdapter,
    RootkitAdapter,
    YaraAdapter,
    YaraXAdapter,
)
from avbox.scanners.base import PreparedScan, ProbeResult, ScannerAdapter
from avbox.scanners.command import CommandResult, IsolatedCommandRunner, store_raw_output


def native(
    stdout: str = "", stderr: str = "", code: int = 0, timeout: bool = False
) -> CommandResult:
    return CommandResult(("detector",), code, stdout, stderr, 0.01, timeout, True)


def result(verdict: Verdict) -> ScannerResult:
    return ScannerResult(
        scanner_id="test",
        native_verdict=verdict,
        normalized_verdict=verdict,
        raw_output_ref="raw-output/test.log",
        runtime_profile="test",
        scanned_at=datetime.now(UTC),
    )


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ([Verdict.CLEAN], Verdict.CLEAN),
        ([Verdict.CLEAN, Verdict.MALICIOUS], Verdict.MALICIOUS),
        ([Verdict.CLEAN, Verdict.SUSPICIOUS], Verdict.SUSPICIOUS),
        ([Verdict.CLEAN, Verdict.PUA], Verdict.PUA),
        ([Verdict.CLEAN, Verdict.ERROR], Verdict.UNKNOWN),
        ([Verdict.ERROR], Verdict.ERROR),
        ([], Verdict.NOT_SCANNED),
    ],
)
def test_aggregate_policy(values: list[Verdict], expected: Verdict) -> None:
    assert aggregate_verdict([result(value) for value in values]) == expected


def test_remediation_arguments_rejected(tmp_path: Path) -> None:
    runner = IsolatedCommandRunner(timeout=1, use_bwrap=False)
    with pytest.raises(ValueError, match="READ_ONLY"):
        runner.run(["scanner", "--remove", "object"], cwd=tmp_path)


def test_timeout_is_bounded(tmp_path: Path) -> None:
    runner = IsolatedCommandRunner(timeout=1, use_bwrap=False)
    value = runner.run(["/bin/sh", "-c", "sleep 5"], cwd=tmp_path)
    assert value.timed_out
    assert value.exit_code == 124


def test_raw_output_is_reference_not_sqlite_blob(tmp_path: Path) -> None:
    reference = store_raw_output(tmp_path, "job", "test", native("untrusted <b>text</b>"))
    output = next((tmp_path / "job").iterdir())
    assert reference.startswith("raw-output/job/")
    assert output.stat().st_mode & 0o777 == 0o400
    assert "<b>" in output.read_text()


def test_clamav_normalization(tmp_path: Path) -> None:
    adapter = ClamAVAdapter(raw_output_root=tmp_path, timeout=1)
    verdict, found = adapter.normalize(native("/object: Eicar-Test-Signature FOUND\n", code=1))
    assert verdict == Verdict.MALICIOUS
    assert found.detection_name == "Eicar-Test-Signature"
    assert found.finding_kind == FindingKind.SIGNATURE_MATCH
    assert adapter.normalize(native(code=0))[0] == Verdict.CLEAN
    assert adapter.normalize(native(code=2))[0] == Verdict.ERROR


@pytest.mark.parametrize("adapter_type", [YaraAdapter, YaraXAdapter])
def test_yara_normalization_and_rule_identity(
    tmp_path: Path, adapter_type: type[YaraAdapter]
) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule harmless { condition: true }", encoding="utf-8")
    adapter = adapter_type(raw_output_root=tmp_path / "raw", timeout=1, rules=rules)
    verdict, match = adapter.normalize(native("harmless object\n"))
    assert verdict == Verdict.SUSPICIOUS
    assert match.finding_kind == FindingKind.RULE_MATCH
    assert adapter.definition_state()["rule_set_sha256"]
    assert adapter.normalize(native())[0] == Verdict.CLEAN


def test_loki_and_maldet_normalization(tmp_path: Path) -> None:
    loki = LokiAdapter(raw_output_root=tmp_path, timeout=1)
    maldet = MaldetAdapter(raw_output_root=tmp_path, timeout=1)
    assert loki.normalize(native("ALERT suspicious indicator"))[0] == Verdict.MALICIOUS
    assert loki.normalize(native("WARNING heuristic"))[0] == Verdict.SUSPICIOUS
    assert maldet.normalize(native("hits: 2"))[0] == Verdict.MALICIOUS
    assert maldet.normalize(native("hits: 0"))[0] == Verdict.CLEAN


def test_system_warning_is_ambiguous(tmp_path: Path) -> None:
    adapter = RootkitAdapter("chkrootkit", "chkrootkit", tmp_path, 1)
    verdict, warning = adapter.normalize(native("eth0: PACKET SNIFFER"))
    assert verdict == Verdict.SUSPICIOUS
    assert warning.finding_kind == FindingKind.ROOTKIT_WARNING
    assert adapter.scanner_class == ScannerClass.SYSTEM_DETECTOR


class FakeAdapter(ScannerAdapter):
    scanner_id = "fake"
    scanner_class = ScannerClass.ANTIVIRUS_ENGINE

    def probe(self) -> ProbeResult:
        return ProbeResult(True, "/fake")

    def capabilities(self) -> set[Capability]:
        return set()

    def prepare(self, *, job_id: str, immutable_input: Path, working_root: Path) -> PreparedScan:
        root = working_root / job_id / self.scanner_id
        root.mkdir(parents=True)
        copy = root / "object"
        copy.write_bytes(immutable_input.read_bytes())
        copy.chmod(0o400)
        return PreparedScan(job_id, immutable_input, copy, {})

    def scan(self, prepared: PreparedScan) -> object:
        return native()

    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]:
        return Verdict.CLEAN, result(Verdict.CLEAN)

    def cleanup(self, prepared: PreparedScan) -> None:
        prepared.working_path.chmod(0o600)
        prepared.working_path.unlink()
        prepared.working_path.parent.rmdir()


def test_scan_lifecycle_preserves_original_and_removes_staging(tmp_path: Path) -> None:
    source = tmp_path / "submitted"
    source.write_bytes(b"harmless")
    source.chmod(0o444)
    service = ScanService(
        jobs=JobService(tmp_path / "jobs.db"),
        adapters={"fake": FakeAdapter()},
        system_adapters={},
        staging=tmp_path / "staging",
        quarantine=PreservationService(tmp_path / "quarantine"),
        maximum_file_bytes=1024,
    )
    job = service.scan_file(source, ["fake", "missing"])
    assert job.normalized_verdict == Verdict.CLEAN
    assert source.read_bytes() == b"harmless"
    assert not (tmp_path / "staging" / str(job.job_id)).exists()
    assert "unavailable" in job.errors[0]
    assert os.stat(source).st_mode & 0o777 == 0o444
