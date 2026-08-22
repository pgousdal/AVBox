from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest
from test_m14_containers import run_container
from test_m14b_disk_images import make_adf, make_fat

from avbox.analyzers.containers import ContainerAnalyzer
from avbox.analyzers.partitions import (
    BoundedRangeReader,
    PartitionTableError,
    hash_range,
    parse_partition_table,
)


def make_mbr(path: Path, partitions: list[bytes]) -> None:
    starts: list[int] = []
    cursor = 2048
    for payload in partitions:
        starts.append(cursor)
        cursor += (len(payload) + 511) // 512
        cursor = ((cursor + 2047) // 2048) * 2048
    image = bytearray(cursor * 512)
    for index, (start, payload) in enumerate(zip(starts, partitions, strict=True)):
        row = 446 + index * 16
        image[row] = 0x80 if index == 0 else 0
        image[row + 4] = 0x06
        struct.pack_into("<II", image, row + 8, start, len(payload) // 512)
        image[start * 512 : start * 512 + len(payload)] = payload
    image[510:512] = b"\x55\xaa"
    path.write_bytes(image)


def _rdb_checksum(block: bytearray) -> None:
    count = struct.unpack_from(">I", block, 4)[0]
    struct.pack_into(">I", block, 8, 0)
    values = struct.unpack(f">{count}I", block[: count * 4])
    struct.pack_into(">I", block, 8, (-sum(values)) & 0xFFFFFFFF)


def make_rdb(path: Path, adf: bytes, *, next_pointer: int = 0xFFFFFFFF) -> None:
    block_size = 512
    cylinder_blocks = len(adf) // block_size
    image = bytearray(len(adf) * 2)
    rdb = bytearray(block_size)
    rdb[:4] = b"RDSK"
    struct.pack_into(">I", rdb, 4, 64)
    struct.pack_into(">I", rdb, 16, block_size)
    struct.pack_into(">I", rdb, 28, 1)
    struct.pack_into(">III", rdb, 64, 2, cylinder_blocks, 1)
    _rdb_checksum(rdb)
    part = bytearray(block_size)
    part[:4] = b"PART"
    struct.pack_into(">I", part, 4, 64)
    struct.pack_into(">I", part, 16, next_pointer)
    part[36:40] = b"\x03DH0"
    env = 128
    struct.pack_into(">I", part, env, 16)
    struct.pack_into(">I", part, env + 4, 128)
    struct.pack_into(">I", part, env + 12, 1)
    struct.pack_into(">I", part, env + 20, cylinder_blocks)
    struct.pack_into(">II", part, env + 36, 1, 1)
    struct.pack_into(">i", part, env + 60, 0)
    part[env + 64 : env + 68] = adf[:4]
    _rdb_checksum(part)
    image[:block_size] = rdb
    image[block_size : 2 * block_size] = part
    image[len(adf) : len(adf) * 2] = adf
    path.write_bytes(image)


def test_bounded_range_reader_and_exact_hashing(tmp_path: Path) -> None:
    source = tmp_path / "root.bin"
    source.write_bytes(b"prefix" + b"partition bytes" + b"suffix")
    with source.open("rb") as stream:
        reader = BoundedRangeReader(stream, 6, 15, source.stat().st_size)
        assert reader.read(9) == b"partition"
        assert reader.read(6) == b" bytes"
        assert reader.read(1) == b""
        with pytest.raises(PartitionTableError):
            reader.seek(-1)
    hashes = hash_range(source, 6, 15)
    assert hashes["sha256"] == hashlib.sha256(b"partition bytes").hexdigest()
    assert len(hashes["blake3"]) == 64


def test_mbr_fat_partition_nested_zip_identity_and_immutability(tmp_path: Path) -> None:
    fat = tmp_path / "fat.img"
    make_fat(fat)
    disk = tmp_path / "disk.raw"
    make_mbr(disk, [fat.read_bytes()])
    before = hashlib.sha256(disk.read_bytes()).hexdigest()
    table = parse_partition_table(disk)
    assert table and table.scheme == "MBR"
    partition = table.partitions[0]
    assert partition.start == 2048 * 512
    job = run_container(tmp_path, disk)
    partition_object = next(item for item in job.derived_objects if item.depth == 1)
    assert partition_object.object.sha256 == hashlib.sha256(fat.read_bytes()).hexdigest()
    assert partition_object.metadata["partition.scheme"] == "MBR"
    assert any(edge.relationship == "PARTITION_OF" for edge in job.relationships)
    assert any(
        edge.relationship == "FILESYSTEM_ENTRY_OF" and edge.depth == 2 for edge in job.relationships
    )
    assert any(item.member_name == "inside.txt" and item.depth == 3 for item in job.derived_objects)
    assert job.completeness == "COMPLETE"
    assert job.extraction_usage.materialized_partition_bytes == len(fat.read_bytes())
    assert hashlib.sha256(disk.read_bytes()).hexdigest() == before


def test_mbr_multiple_overlap_corruption_and_partial_sibling(tmp_path: Path) -> None:
    fat = tmp_path / "fat.img"
    make_fat(fat)
    disk = tmp_path / "two.raw"
    make_mbr(disk, [fat.read_bytes(), fat.read_bytes()])
    job = run_container(tmp_path, disk, max_total_children=30)
    partitions = [item for item in job.derived_objects if item.depth == 1]
    assert len(partitions) == 2
    assert partitions[0].object.sha256 == partitions[1].object.sha256
    assert len([edge for edge in job.relationships if edge.relationship == "PARTITION_OF"]) == 2

    damaged = bytearray(disk.read_bytes())
    struct.pack_into("<II", damaged, 446 + 16 + 8, len(damaged) // 512 + 1, 10)
    disk.write_bytes(damaged)
    partial = run_container(tmp_path, disk)
    assert partial.completeness == "PARTIAL_ERROR"
    assert any(item.depth == 1 for item in partial.derived_objects)
    assert partial.normalized_verdict.value == "NOT_SCANNED"

    damaged[510:512] = b"\0\0"
    disk.write_bytes(damaged)
    assert ContainerAnalyzer._kind(disk) == "partitioned-disk"
    assert run_container(tmp_path, disk).completeness == "PARTIAL_ERROR"

    ordinary = tmp_path / "ordinary.bin"
    ordinary.write_bytes(b"A" * 1024)
    assert ContainerAnalyzer._kind(ordinary) is None


def test_rdb_ffs_partition_lha_metadata_and_cycle_defense(tmp_path: Path) -> None:
    adf_path = tmp_path / "ffs.adf"
    make_adf(adf_path, "FFS")
    hdf = tmp_path / "disk.hdf"
    make_rdb(hdf, adf_path.read_bytes())
    before = hashlib.sha256(hdf.read_bytes()).hexdigest()
    table = parse_partition_table(hdf)
    assert table and table.scheme == "RDB"
    assert table.partitions[0].name == "DH0"
    assert table.partitions[0].metadata["rdb.dostype"] == "DOS\\1"
    job = run_container(tmp_path, hdf, use_bubblewrap=False)
    assert any(edge.relationship == "PARTITION_OF" for edge in job.relationships)
    assert any(
        item.member_name == "ARCHIVE.LHA" and item.depth == 2 for item in job.derived_objects
    )
    assert any(
        item.member_name == "lha-child.txt" and item.depth == 3 for item in job.derived_objects
    )
    assert hashlib.sha256(hdf.read_bytes()).hexdigest() == before

    make_rdb(hdf, adf_path.read_bytes(), next_pointer=1)
    cycled = parse_partition_table(hdf)
    assert cycled and "RDB partition pointer cycle" in cycled.errors


def test_rdb_bad_pointer_geometry_and_checksum(tmp_path: Path) -> None:
    adf_path = tmp_path / "ofs.adf"
    make_adf(adf_path, "OFS")
    hdf = tmp_path / "disk.hdf"
    make_rdb(hdf, adf_path.read_bytes())
    damaged = bytearray(hdf.read_bytes())
    struct.pack_into(">I", damaged, 28, len(damaged) // 512 + 1)
    block = bytearray(damaged[:512])
    _rdb_checksum(block)
    damaged[:512] = block
    hdf.write_bytes(damaged)
    table = parse_partition_table(hdf)
    assert table and "RDB partition pointer lies outside image" in table.errors

    damaged[8] ^= 1
    hdf.write_bytes(damaged)
    with pytest.raises(PartitionTableError, match="checksum"):
        parse_partition_table(hdf)


def test_partition_global_materialization_budget(tmp_path: Path) -> None:
    fat = tmp_path / "fat.img"
    make_fat(fat)
    disk = tmp_path / "disk.raw"
    make_mbr(disk, [fat.read_bytes()])
    job = run_container(tmp_path, disk, max_materialized_partition_bytes=1024)
    assert not job.derived_objects
    assert "PARTITION_MATERIALIZATION_LIMIT" in job.extraction_usage.limit_events
    assert job.completeness == "PARTIAL_LIMIT"
