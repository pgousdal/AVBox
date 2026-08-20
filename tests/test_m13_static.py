from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from avbox.analyzers.static import ByteStatisticsAnalyzer, StringsAnalyzer
from avbox.config import AppSettings
from avbox.models import Hashes, InputArtifact


def make_artifact(size: int) -> InputArtifact:
    return InputArtifact(
        hashes=Hashes(sha256="a" * 64, blake3="b" * 64, sha1="c" * 40, md5="d" * 32),
        byte_size=size,
        filename="fixture.bin",
        media_type="application/octet-stream",
        source="test",
        submitted_at=datetime.now(UTC),
    )


def observations(result: object) -> dict[str, list[object]]:
    values: dict[str, list[object]] = {}
    for item in result.observations:
        values.setdefault(item.observation_type, []).append(item.value)
    return values


def analyzers() -> tuple[StringsAnalyzer, ByteStatisticsAnalyzer]:
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    return StringsAnalyzer(settings), ByteStatisticsAnalyzer()


def test_entropy_is_deterministic_and_neutral(tmp_path: Path) -> None:
    source = tmp_path / "zeros"
    source.write_bytes(bytes(4096))
    result = analyzers()[1].analyze(make_artifact(4096), source, "entropy")
    values = observations(result)
    assert values["byte.entropy.shannon"] == [0.0]
    assert values["byte.unique_count"] == [1]
    assert result.normalized_verdict is None

    source.write_bytes(bytes(range(256)) * 16)
    high = analyzers()[1].analyze(make_artifact(4096), source, "high")
    assert abs(observations(high)["byte.entropy.shannon"][0] - 8.0) < 1e-6


def test_strings_support_ascii_and_utf16(tmp_path: Path) -> None:
    source = tmp_path / "strings"
    source.write_bytes(b"xx ASCII-marker xx\x00" + "UTF16LE-marker".encode("utf-16le"))
    result = analyzers()[0].analyze(make_artifact(source.stat().st_size), source, "strings")
    values = observations(result)["strings.value"]
    assert any(item["encoding"] == "ASCII" and "ASCII-marker" in item["value"] for item in values)
    assert any(
        item["encoding"] == "UTF-16LE" and "UTF16LE-marker" in item["value"] for item in values
    )
    assert not result.errors


def test_strings_are_bounded_and_mark_truncation(tmp_path: Path) -> None:
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    settings.runtime.strings_max_count = 2
    settings.runtime.strings_max_total_chars = 10
    source = tmp_path / "many"
    source.write_bytes(b"alpha bravo charlie delta")
    result = StringsAnalyzer(settings).analyze(
        make_artifact(source.stat().st_size), source, "bounded"
    )
    values = observations(result)
    assert values["strings.count_returned"][0] <= 2
    assert values["strings.truncated"] == [True]
    assert any(item.assessment_type == "STRING_OUTPUT_TRUNCATED" for item in result.assessments)
    assert result.normalized_verdict is None


def test_control_and_markup_strings_remain_inert(tmp_path: Path) -> None:
    source = tmp_path / "inert"
    source.write_bytes(b"<script>alert(1)</script>\x1b[31m$ sh -c evil")
    result = analyzers()[0].analyze(make_artifact(source.stat().st_size), source, "inert")
    text = " ".join(item["value"] for item in observations(result)["strings.value"])
    assert "<script>" in text
    assert result.findings == []
    assert result.normalized_verdict is None


def test_static_profile_and_identity_remain_distinct() -> None:
    import yaml

    document = yaml.safe_load(Path("config/analysis-profiles.yaml").read_text())
    profile = next(item for item in document["profiles"] if item["id"] == "static-default")
    assert profile["version"] == 1
    assert profile["analyzers"] == [
        "identity",
        "basic-metadata",
        "file-type",
        "strings",
        "byte-statistics",
        "generic-metadata",
        "similarity",
    ]
    assert "security-default" not in profile["analyzers"]
