from __future__ import annotations

import hashlib
import io
import struct
import zipfile
from pathlib import Path

import pytest
from test_m14_containers import run_container

from avbox.analyzers.executable import ExecutableAnalyzer, ExecutableError, parse_executable
from avbox.application.artifacts import ArtifactService


def make_pe(*, is64: bool = False, machine: int | None = None) -> bytes:
    pe_offset = 0x80
    optional_size = 240 if is64 else 224
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<H", data, 8, 4)
    struct.pack_into("<H", data, 24, 0x40)
    struct.pack_into("<I", data, 60, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        pe_offset + 4,
        machine or (0x8664 if is64 else 0x014C),
        1,
        0x12345678,
        0,
        0,
        optional_size,
        0x0102,
    )
    optional = pe_offset + 24
    struct.pack_into("<H", data, optional, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    if is64:
        struct.pack_into("<Q", data, optional + 24, 0x140000000)
    else:
        struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<HH", data, optional + 68, 3, 0x8140)
    struct.pack_into("<I", data, optional + (108 if is64 else 92), 16)
    section = optional + optional_size
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x20, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200] = 0xC3
    return bytes(data)


def make_elf(*, is64: bool = True, machine: int | None = None) -> bytes:
    data = bytearray(64 if is64 else 52)
    data[:4] = b"\x7fELF"
    data[4:9] = bytes([2 if is64 else 1, 1, 1, 0, 0])
    if is64:
        struct.pack_into(
            "<HHIQQQIHHHHHH",
            data,
            16,
            2,
            machine or 62,
            1,
            0x401000,
            0,
            0,
            0,
            64,
            56,
            0,
            64,
            0,
            0,
        )
    else:
        struct.pack_into(
            "<HHIIIIIHHHHHH",
            data,
            16,
            2,
            machine or 3,
            1,
            0x8048000,
            0,
            0,
            0,
            52,
            32,
            0,
            40,
            0,
            0,
        )
    return bytes(data)


def make_mz(extension: bytes | None = None) -> bytes:
    size = 0x180 if extension else 64
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<HH", data, 2, size % 512, 1)
    struct.pack_into("<H", data, 8, 4)
    struct.pack_into("<H", data, 24, 0x40)
    if extension:
        struct.pack_into("<I", data, 60, 0x80)
        data[0x80 : 0x80 + len(extension)] = extension
    return bytes(data)


def make_hunk() -> bytes:
    values = [
        0x3F3,
        0,
        3,
        0,
        2,
        1,
        1,
        2,
        0x3E9,
        1,
        0x4E754E71,
        0x3EC,
        1,
        1,
        0,
        0,
        0x3F0,
        1,
        0x73796D00,
        0,
        0,
        0x3F2,
        0x3EA,
        1,
        0x12345678,
        0x3F2,
        0x3EB,
        2,
        0x3F2,
    ]
    return struct.pack(f">{len(values)}I", *values)


@pytest.mark.parametrize(
    ("payload", "expected_format", "architecture"),
    [
        (make_pe(), "PE32", "I386"),
        (make_pe(is64=True), "PE32+", "AMD64"),
        (make_elf(is64=False), "ELF32", "I386"),
        (make_elf(), "ELF64", "X86_64"),
        (make_mz(), "DOS_MZ", "X86_16"),
        (make_hunk(), "AMIGA_HUNK", "M68K"),
    ],
)
def test_primary_executable_formats(
    payload: bytes, expected_format: str, architecture: str
) -> None:
    parsed = parse_executable(payload)
    assert parsed and parsed.format == expected_format
    assert parsed.architecture == architecture


def test_pe_sections_directories_overlay_and_unknown_machine() -> None:
    parsed = parse_executable(make_pe(machine=0x1C4))
    assert parsed and parsed.architecture == "COFF_MACHINE_0x01C4"
    values = dict(parsed.observations)
    assert values["pe.coff"]["section_count"] == 1
    assert values["pe.sections"][0] == {
        "index": 0,
        "name": ".text",
        "rva": 0x1000,
        "virtual_size": 0x20,
        "raw_offset": 0x200,
        "raw_size": 0x200,
        "characteristics": 0x60000020,
    }
    assert values["pe.overlay"] == {"present": False, "offset": 0x400, "size": 0}


def test_pe_import_library_symbol_and_directory_presence() -> None:
    data = bytearray(make_pe())
    optional = 0x80 + 24
    struct.pack_into("<II", data, optional + 96 + 8, 0x1020, 40)
    struct.pack_into("<IIIII", data, 0x220, 0x1090, 0, 0, 0x1080, 0x1090)
    data[0x280:0x28D] = b"KERNEL32.DLL\0"
    struct.pack_into("<II", data, 0x290, 0x10A0, 0)
    struct.pack_into("<H", data, 0x2A0, 0)
    data[0x2A2:0x2AE] = b"ExitProcess\0"
    parsed = parse_executable(bytes(data))
    assert parsed
    values = dict(parsed.observations)
    assert values["pe.imports"] == [{"library": "KERNEL32.DLL", "symbols": ["ExitProcess"]}]


def test_elf_real_host_structure_when_available() -> None:
    candidate = Path("/bin/true")
    if not candidate.exists():
        pytest.skip("host ELF fixture unavailable")
    parsed = parse_executable(candidate.read_bytes())
    assert parsed and parsed.format == "ELF64"
    values = dict(parsed.observations)
    assert values["elf.program_headers"]
    assert values["elf.sections"]
    assert values["elf.interpreter"]
    assert values["elf.dynamic"]["needed"]


def test_mz_ne_le_lx_and_pe_distinction() -> None:
    ne = bytearray(64)
    ne[:2] = b"NE"
    le = bytearray(176)
    le[:2] = b"LE"
    struct.pack_into("<H", le, 8, 2)
    lx = bytearray(le)
    lx[:2] = b"LX"
    assert parse_executable(make_mz(bytes(ne))).format == "NE"
    assert parse_executable(make_mz(bytes(le))).format == "LE"
    assert parse_executable(make_mz(bytes(lx))).format == "LX"
    assert parse_executable(make_pe()).format == "PE32"


def test_hunk_code_data_bss_relocation_symbol_and_end() -> None:
    parsed = parse_executable(make_hunk())
    assert parsed and parsed.format == "AMIGA_HUNK"
    values = dict(parsed.observations)
    assert values["hunk.header"]["hunk_count"] == 3
    records = values["hunk.records"]
    assert {item["type"] for item in records} >= {
        "HUNK_CODE",
        "HUNK_DATA",
        "HUNK_BSS",
        "HUNK_RELOC32",
        "HUNK_SYMBOL",
        "HUNK_END",
    }
    assert next(item for item in records if item["type"] == "HUNK_BSS")["size_bytes"] == 8


def test_unknown_hunk_type_is_preserved_numerically() -> None:
    values = [0x3F3, 0, 1, 0, 0, 0, 0x1234]
    parsed = parse_executable(struct.pack(f">{len(values)}I", *values))
    assert parsed
    record = dict(parsed.observations)["hunk.records"][0]
    assert record == {
        "type_id": 0x1234,
        "type": "HUNK_UNKNOWN_4660",
        "memory_flags": 0,
        "hunk_index": 0,
        "unsupported": True,
    }
    assert parsed.errors == ["unsupported HUNK record type 4660"]


@pytest.mark.parametrize(
    "payload",
    [
        b"MZ",
        make_pe()[:200],
        make_elf()[:30],
        make_hunk()[:-4],
        b"\xfe\xed\xfa\xcf" + b"\0" * 10,
    ],
)
def test_truncated_recognized_executables_are_precise(payload: bytes) -> None:
    with pytest.raises(ExecutableError, match="truncated|lacks"):
        parse_executable(payload)


def test_analyzer_observations_do_not_create_security_verdict(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    source.write_bytes(make_pe())
    artifact = ArtifactService.hash_file(source)
    before = artifact.hashes.sha256
    result = ExecutableAnalyzer(1024 * 1024).analyze(artifact, source, "job")
    assert result.native_status == "complete"
    assert result.normalized_verdict is None
    assert not result.findings
    assert ArtifactService.hash_file(source).hashes.sha256 == before


def test_executable_parser_limit_and_non_executable(tmp_path: Path) -> None:
    source = tmp_path / "large.exe"
    source.write_bytes(make_pe() + b"X" * 2048)
    artifact = ArtifactService.hash_file(source)
    limited = ExecutableAnalyzer(1024).analyze(artifact, source, "job")
    assert limited.native_status == "unsupported_limit"
    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_text("hello")
    result = ExecutableAnalyzer(1024).analyze(ArtifactService.hash_file(ordinary), ordinary, "job")
    assert result.native_status == "not_applicable"
    assert not result.errors


def test_recursive_zip_child_retains_executable_identity(tmp_path: Path) -> None:
    source = tmp_path / "nested.zip"
    payload = make_pe()
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("bin/hello.exe", payload)
    job = run_container(tmp_path, source)
    child = next(item for item in job.derived_objects if item.member_name == "bin/hello.exe")
    assert child.object.sha256 == hashlib.sha256(payload).hexdigest()
    assert any(edge.target_sha256 == child.object.sha256 for edge in job.relationships)


def test_hunk_can_be_nested_in_lha_bytes() -> None:
    # The qualified LHA integration test supplies external extraction; this
    # confirms the exact extracted payload is independently parseable as HUNK.
    stream = io.BytesIO(make_hunk())
    assert parse_executable(stream.read()).format == "AMIGA_HUNK"
