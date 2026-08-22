from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest
from test_m14b_disk_images import _checksum, make_adf, make_fat, make_lh0
from test_m14c_partitions import _rdb_checksum, make_rdb

from avbox.analyzers.partitions import parse_partition_table
from avbox.analyzers.structural import StructuralValidator
from avbox.application.artifacts import ArtifactService
from avbox.models import ScannerClass, StructuralState


def validate(path: Path):
    result = StructuralValidator().analyze(ArtifactService.hash_file(path), path, "test")
    assert result.analyzer_class == ScannerClass.STRUCTURAL_VALIDATOR
    assert result.normalized_verdict is None
    assert result.structural_validation is not None
    assert (
        result.structural_validation.source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    return result.structural_validation


@pytest.mark.parametrize("variant", ["OFS", "FFS"])
def test_adf_clean_and_damage_matrix(tmp_path: Path, variant: str) -> None:
    source = tmp_path / f"{variant}.adf"
    make_adf(source, variant)
    before = source.read_bytes()
    clean = validate(source)
    assert clean.variant == variant
    assert clean.state == StructuralState.VALID
    assert source.read_bytes() == before

    cases = {
        "boot": (4, "BOOTBLOCK_CHECKSUM_MISMATCH"),
        "root": (880 * 512 + 20, "ROOTBLOCK_CHECKSUM_MISMATCH"),
        "bitmap": (879 * 512 + 20, "ADF_BITMAP_CHECKSUM_MISMATCH"),
        "pointer": (880 * 512 + 24, "ADF_BLOCK_REFERENCE_OUT_OF_RANGE"),
    }
    for name, (offset, expected) in cases.items():
        damaged = bytearray(before)
        if name == "pointer":
            struct.pack_into(">I", damaged, offset, 999999)
        else:
            damaged[offset] ^= 1
        path = tmp_path / f"{variant}-{name}.adf"
        path.write_bytes(damaged)
        outcome = validate(path)
        assert outcome.state == StructuralState.DAMAGED
        assert expected in {item.finding_type for item in outcome.findings}

    truncated = tmp_path / f"{variant}-truncated.adf"
    truncated.write_bytes(before[:-512])
    assert validate(truncated).state == StructuralState.TRUNCATED

    loop = bytearray(before)
    struct.pack_into(">I", loop, 880 * 512 + 24, 880)
    root = bytearray(loop[880 * 512 : 881 * 512])
    _checksum(root)
    loop[880 * 512 : 881 * 512] = root
    loop_path = tmp_path / f"{variant}-loop.adf"
    loop_path.write_bytes(loop)
    assert "ADF_CHAIN_LOOP" in {x.finding_type for x in validate(loop_path).findings}


@pytest.mark.parametrize("variant", ["FAT12", "FAT16", "FAT32"])
def test_fat_clean_copy_mismatch_crosslink_loop_invalid_and_truncation(
    tmp_path: Path, variant: str
) -> None:
    source = tmp_path / f"{variant}.img"
    make_fat(source, variant)
    original = source.read_bytes()
    assert validate(source).state == StructuralState.VALID

    bps = 512
    reserved = int.from_bytes(original[14:16], "little")
    fat_size = int.from_bytes(original[22:24], "little") or int.from_bytes(
        original[36:40], "little"
    )
    mismatch = bytearray(original)
    mismatch[(reserved + fat_size) * bps + 10] ^= 1
    path = tmp_path / f"{variant}-copies.img"
    path.write_bytes(mismatch)
    assert "FAT_COPIES_MISMATCH" in {x.finding_type for x in validate(path).findings}

    truncated = tmp_path / f"{variant}-truncated.img"
    truncated.write_bytes(original[:-512])
    assert validate(truncated).state == StructuralState.TRUNCATED

    def set_entry(image: bytearray, cluster: int, value: int) -> None:
        offset = reserved * bps
        if variant == "FAT12":
            pos = offset + cluster + cluster // 2
            current = int.from_bytes(image[pos : pos + 2], "little")
            current = (
                (current & 0x000F) | (value << 4) if cluster & 1 else (current & 0xF000) | value
            )
            image[pos : pos + 2] = current.to_bytes(2, "little")
        elif variant == "FAT16":
            struct.pack_into("<H", image, offset + cluster * 2, value)
        else:
            struct.pack_into("<I", image, offset + cluster * 4, value)

    root_cluster = 4 if variant == "FAT32" else 3
    loop = bytearray(original)
    set_entry(loop, root_cluster, root_cluster)
    path.write_bytes(loop)
    assert "FAT_CLUSTER_CHAIN_LOOP" in {x.finding_type for x in validate(path).findings}

    invalid = bytearray(original)
    set_entry(invalid, root_cluster, 0xFF0 if variant == "FAT12" else 0xFFF0)
    path.write_bytes(invalid)
    assert "FAT_CLUSTER_REFERENCE_INVALID" in {x.finding_type for x in validate(path).findings}

    crosslink = bytearray(original)
    root_entries = int.from_bytes(original[17:19], "little")
    root_sectors = (root_entries * 32 + 511) // 512
    first_data = reserved + 2 * fat_size + root_sectors
    root_offset = first_data * 512 if variant == "FAT32" else (reserved + 2 * fat_size) * 512
    first = int.from_bytes(
        crosslink[root_offset + 3 * 32 + 26 : root_offset + 3 * 32 + 28], "little"
    )
    struct.pack_into("<H", crosslink, root_offset + 4 * 32 + 26, first)
    path.write_bytes(crosslink)
    assert "FAT_CROSSLINK_DETECTED" in {x.finding_type for x in validate(path).findings}


def test_rdb_checksum_part_cycle_bounds_and_data_only(tmp_path: Path) -> None:
    adf = tmp_path / "partition.adf"
    make_adf(adf, "FFS")
    source = tmp_path / "disk.hdf"
    make_rdb(source, adf.read_bytes())
    clean = validate(source)
    assert clean.state == StructuralState.VALID
    assert (
        next(
            x.value
            for x in clean.observations
            if x.observation_type == "RDB_EMBEDDED_FILESYSTEM_CODE"
        )
        == "DATA_ONLY"
    )

    bad = bytearray(source.read_bytes())
    bad[8] ^= 1
    damaged = tmp_path / "bad-rdb.hdf"
    damaged.write_bytes(bad)
    assert "RDB_CHECKSUM_MISMATCH" in {x.finding_type for x in validate(damaged).findings}

    cycle = bytearray(source.read_bytes())
    struct.pack_into(">I", cycle, 512 + 16, 1)
    part = bytearray(cycle[512:1024])
    _rdb_checksum(part)
    cycle[512:1024] = part
    damaged.write_bytes(cycle)
    assert "RDB_POINTER_CYCLE" in {x.finding_type for x in validate(damaged).findings}

    bad_part = bytearray(source.read_bytes())
    bad_part[512 + 8] ^= 1
    damaged.write_bytes(bad_part)
    assert "RDB_PART_CHECKSUM_OR_STRUCTURE_INVALID" in {
        x.finding_type for x in validate(damaged).findings
    }

    outside = bytearray(source.read_bytes())
    struct.pack_into(">I", outside, 512 + 128 + 40, 9999)
    part = bytearray(outside[512:1024])
    _rdb_checksum(part)
    outside[512:1024] = part
    damaged.write_bytes(outside)
    assert "RDB_POINTER_OR_PARTITION_OUT_OF_RANGE" in {
        x.finding_type for x in validate(damaged).findings
    }

    # A valid first PART remains attributable when a later sibling is damaged.
    siblings = tmp_path / "siblings.hdf"
    make_rdb(siblings, adf.read_bytes(), next_pointer=2)
    sibling_data = bytearray(siblings.read_bytes())
    sibling_data[2 * 512 : 2 * 512 + 4] = b"PART"
    siblings.write_bytes(sibling_data)
    table = parse_partition_table(siblings)
    assert table is not None
    assert len(table.partitions) == 1
    assert table.partitions[0].name == "DH0"
    assert "invalid RDB PART block at 2" in table.errors
    assert "RDB_PART_CHECKSUM_OR_STRUCTURE_INVALID" in {
        x.finding_type for x in validate(siblings).findings
    }


def _iso(path: Path) -> None:
    image = bytearray(24 * 2048)
    pvd = memoryview(image)[16 * 2048 : 17 * 2048]
    pvd[0] = 1
    pvd[1:6] = b"CD001"
    pvd[6] = 1
    struct.pack_into("<I", pvd, 80, 24)
    struct.pack_into("<H", pvd, 128, 2048)
    root = bytearray(34)
    root[0] = 34
    struct.pack_into("<I", root, 2, 20)
    struct.pack_into("<I", root, 10, 2048)
    root[25] = 2
    root[32:34] = b"\x01\x00"
    pvd[156:190] = root
    term = memoryview(image)[17 * 2048 : 18 * 2048]
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    image[20 * 2048 : 20 * 2048 + 34] = root
    path.write_bytes(image)


def test_iso_and_lha_validation(tmp_path: Path) -> None:
    iso = tmp_path / "valid.iso"
    _iso(iso)
    assert validate(iso).state == StructuralState.VALID
    bad_iso = bytearray(iso.read_bytes())
    struct.pack_into("<I", bad_iso, 16 * 2048 + 156 + 2, 1000)
    iso.write_bytes(bad_iso)
    assert "ISO_DIRECTORY_EXTENT_OUT_OF_RANGE" in {x.finding_type for x in validate(iso).findings}

    fresh = tmp_path / "fresh.iso"
    _iso(fresh)
    malformed = bytearray(fresh.read_bytes())
    malformed[20 * 2048] = 5
    iso.write_bytes(malformed)
    assert "ISO_DIRECTORY_RECORD_MALFORMED" in {x.finding_type for x in validate(iso).findings}

    descriptor = bytearray(fresh.read_bytes())
    descriptor[17 * 2048 + 1] ^= 1
    iso.write_bytes(descriptor)
    assert "ISO_VOLUME_DESCRIPTOR_INVALID" in {x.finding_type for x in validate(iso).findings}

    iso.write_bytes(fresh.read_bytes()[:-2048])
    assert "ISO_VOLUME_SPACE_OUT_OF_RANGE" in {x.finding_type for x in validate(iso).findings}

    lha = tmp_path / "valid.lha"
    lha.write_bytes(make_lh0("safe.txt", b"harmless"))
    assert validate(lha).state == StructuralState.VALID
    bad_lha = bytearray(lha.read_bytes())
    bad_lha[-2] ^= 1
    lha.write_bytes(bad_lha)
    assert "LHA_MEMBER_CRC_MISMATCH" in {x.finding_type for x in validate(lha).findings}
    lha.write_bytes(bytes(bad_lha[:-4]))
    assert validate(lha).state == StructuralState.TRUNCATED

    malformed_lha = bytearray(make_lh0("safe.txt", b"harmless"))
    malformed_lha[0] = 1
    lha.write_bytes(malformed_lha)
    assert "LHA_HEADER_MALFORMED" in {x.finding_type for x in validate(lha).findings}


def test_structural_state_is_not_security_verdict_and_unknown_is_unsupported(
    tmp_path: Path,
) -> None:
    ordinary = tmp_path / "ordinary.bin"
    ordinary.write_bytes(b"not historical media")
    result = StructuralValidator().analyze(ArtifactService.hash_file(ordinary), ordinary, "test")
    assert result.native_status == "unsupported"
    assert result.normalized_verdict is None
    assert result.structural_validation is None
