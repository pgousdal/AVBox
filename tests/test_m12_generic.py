from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from avbox.analyzers import build_generic_analyzers
from avbox.analyzers.generic import FileMagicAnalyzer, IdentityAnalyzer, MetadataAnalyzer
from avbox.config import AppSettings
from avbox.models import Confidence, Hashes, InputArtifact
from avbox.scanners.command import CommandResult


def artifact(
    *,
    filename: str = "object.bin",
    submitted_filename: str | None = None,
    media_type: str = "application/octet-stream",
    size: int = 4,
) -> InputArtifact:
    return InputArtifact(
        hashes=Hashes(
            sha256="1" * 64,
            blake3="2" * 64,
            sha1="3" * 40,
            md5="4" * 32,
        ),
        byte_size=size,
        filename=filename,
        submitted_filename=submitted_filename,
        media_type=media_type,
        source="test",
        submitted_at=datetime.now(UTC),
    )


class FakeFileRunner:
    def __init__(
        self,
        description: str = "ASCII text",
        mime_type: str = "text/plain",
        encoding: str = "us-ascii",
        *,
        fail: bool = False,
        timeout: bool = False,
    ):
        self.values = {
            "description": description,
            "mime_type": mime_type,
            "encoding": encoding,
        }
        self.fail = fail
        self.timeout = timeout

    def run(self, argv: list[str], *, cwd: Path, read_only_input: Path | None = None):
        del cwd, read_only_input
        if "--version" in argv:
            return CommandResult(
                tuple(argv), 0, "file-5.46\nmagic file from /usr/share/misc/magic\n", "", 0.01
            )
        mode = (
            "mime_type"
            if "--mime-type" in argv
            else "encoding"
            if "--mime-encoding" in argv
            else "description"
        )
        return CommandResult(
            tuple(argv),
            1 if self.fail else 0,
            "" if self.fail else self.values[mode] + "\n",
            "failure" if self.fail else "",
            0.01,
            timed_out=self.timeout,
            isolated=True,
        )


class MissingFileRunner:
    def run(self, argv: list[str], *, cwd: Path, read_only_input: Path | None = None):
        del argv, cwd, read_only_input
        raise FileNotFoundError("file not installed")


def magic(tmp_path: Path, runner: FakeFileRunner) -> FileMagicAnalyzer:
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    analyzer = FileMagicAnalyzer(settings)
    analyzer.raw_output_root = tmp_path / "raw"
    analyzer.runner = runner  # type: ignore[assignment]
    return analyzer


def kinds(result: object) -> dict[str, object]:
    observations = result.observations
    return {value.observation_type: value.value for value in observations}


def test_identity_uses_verified_ingestion_without_rehash(tmp_path: Path) -> None:
    source = tmp_path / "changed-or-unavailable"
    result = IdentityAnalyzer().analyze(artifact(), source, "job")
    assert kinds(result)["identity.sha256"] == "1" * 64
    assert all(value.confidence == "exact" for value in result.observations)


def test_filename_metadata_unicode_traversal_and_multiple_extensions(tmp_path: Path) -> None:
    del tmp_path
    result = MetadataAnalyzer().analyze(
        artifact(submitted_filename="../../résumé.\u0065\u0301.pdf.exe"), Path("unused"), "job"
    )
    values = kinds(result)
    assert values["filename.original"].startswith("../../")
    assert values["filename.basename"].endswith(".pdf.exe")
    assert values["filename.extension"] == "exe"
    assert [value.assessment_type for value in result.assessments] == ["MULTIPLE_EXTENSION"]


def test_compound_extension_is_intentional_not_ambiguous() -> None:
    result = MetadataAnalyzer().analyze(
        artifact(submitted_filename="archive.tar.gz"), Path("unused"), "job"
    )
    assert kinds(result)["filename.compound_extension"] == "tar.gz"
    assert not result.assessments


def test_file_magic_text_and_declared_mime_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "object"
    source.write_bytes(b"hello")
    result = magic(tmp_path, FakeFileRunner()).analyze(
        artifact(filename="photo.jpg", media_type="image/jpeg", size=5), source, "job"
    )
    values = kinds(result)
    assert values["file.magic.description"] == "ASCII text"
    assert values["file.mime.type"] == "text/plain"
    assessment_kinds = {value.assessment_type for value in result.assessments}
    assert {
        "FILE_TYPE",
        "EXTENSION_TYPE_MISMATCH",
        "DECLARED_MEDIA_TYPE_MISMATCH",
    } <= assessment_kinds
    assert result.normalized_verdict is None


def test_empty_and_pe_platform_architecture_hints(tmp_path: Path) -> None:
    source = tmp_path / "object"
    source.write_bytes(b"")
    empty = magic(tmp_path, FakeFileRunner("empty", "inode/x-empty", "binary")).analyze(
        artifact(size=0), source, "empty"
    )
    assert empty.assessments[0].statement == "family=empty; format=EMPTY"
    pe = magic(
        tmp_path,
        FakeFileRunner(
            "PE32 executable (GUI) Intel 80386, for MS Windows",
            "application/vnd.microsoft.portable-executable",
            "binary",
        ),
    ).analyze(artifact(filename="safe.exe"), source, "pe")
    by_kind = {value.assessment_type: value for value in pe.assessments}
    assert by_kind["PLATFORM_HINT"].statement == "windows"
    assert by_kind["ARCHITECTURE_HINT"].statement == "x86"
    assert by_kind["FILE_TYPE"].confidence == Confidence.HIGH
    assert pe.normalized_verdict is None


def test_libmagic_failure_is_explicit_and_retains_other_analyzers(tmp_path: Path) -> None:
    source = tmp_path / "object"
    source.write_bytes(b"safe")
    failed = magic(tmp_path, FakeFileRunner(fail=True)).analyze(artifact(), source, "job")
    identity = IdentityAnalyzer().analyze(artifact(), source, "job")
    assert failed.native_status == "error"
    assert failed.errors == ["file-command-failed"]
    assert not failed.observations
    assert kinds(identity)["object.size"] == 4


def test_libmagic_timeout_and_malformed_output_are_explicit(tmp_path: Path) -> None:
    source = tmp_path / "object"
    source.write_bytes(b"safe")
    timed = magic(tmp_path, FakeFileRunner(timeout=True)).analyze(artifact(), source, "timed")
    malformed = magic(
        tmp_path, FakeFileRunner(description="", mime_type="", encoding="")
    ).analyze(artifact(), source, "malformed")
    assert timed.errors == ["analyzer-timeout"]
    assert malformed.errors == ["malformed-output"]
    assert timed.normalized_verdict is None


def test_libmagic_unavailable_is_explicit(tmp_path: Path) -> None:
    source = tmp_path / "object"
    source.write_bytes(b"safe")
    analyzer = magic(tmp_path, FakeFileRunner())
    analyzer.runner = MissingFileRunner()  # type: ignore[assignment]
    assert not analyzer.probe().available
    result = analyzer.analyze(artifact(), source, "missing")
    assert result.qualification_state == "NOT_INSTALLED"
    assert result.errors[0].startswith("analyzer-unavailable")


def test_profiles_are_versioned_and_security_v1_is_unchanged() -> None:
    import yaml

    document = yaml.safe_load(Path("config/analysis-profiles.yaml").read_text())
    profiles = {f"{value['id']}@{value['version']}": value for value in document["profiles"]}
    assert profiles["security-default@1"]["analyzers"] == ["clamav", "yara"]
    assert profiles["identification-default@1"]["analyzers"] == [
        "identity",
        "basic-metadata",
        "file-type",
    ]


def test_protocol_v1_maps_generic_results_without_security_verdict(tmp_path: Path) -> None:
    from test_rab_protocol import protocol_service, submit

    service, _ = protocol_service(tmp_path)
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    analyzers = build_generic_analyzers(settings)
    file_type = analyzers["file-type"]
    assert isinstance(file_type, FileMagicAnalyzer)
    file_type.raw_output_root = tmp_path / "raw"
    file_type.runner = FakeFileRunner()  # type: ignore[assignment]
    service.scans.generic_analyzers = analyzers
    accepted = submit(
        service,
        b"harmless text",
        profile_id="identification-default@1",
        filename="note.txt",
    )
    service.queue.join()
    result = service.results(str(accepted.job_id))
    assert result.profile == "identification-default@1"
    assert result.verdict is None
    assert {value.analyzer_id for value in result.analyzers} == {
        "identity",
        "basic-metadata",
        "file-type",
    }
    observed = {value.observation_type for value in result.observations}
    assert {"identity.sha256", "filename.extension", "file.mime.type"} <= observed
