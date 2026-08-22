from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO


class PartitionTableError(ValueError):
    """A recognized partition table is unsafe or structurally damaged."""


class BoundedRangeReader:
    """Seekable, read-only view which cannot escape one root-file byte range."""

    def __init__(self, stream: BinaryIO, start: int, length: int, root_size: int):
        if start < 0 or length < 0 or start > root_size or length > root_size - start:
            raise PartitionTableError("byte range lies outside root object")
        self._stream = stream
        self.start = start
        self.length = length
        self.root_size = root_size
        self._position = 0

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            target = offset
        elif whence == 1:
            target = self._position + offset
        else:
            target = self.length + offset
        if target < 0 or target > self.length:
            raise PartitionTableError("seek lies outside bounded byte range")
        self._position = target
        return target

    def tell(self) -> int:
        return self._position

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = self.length - self._position
        if size < 0:
            raise PartitionTableError("negative read size")
        size = min(size, self.length - self._position)
        end = self._position + size
        self._stream.seek(self.start + self._position)
        value = self._stream.read(size)
        if len(value) != size:
            raise PartitionTableError("root object was truncated during range read")
        self._position = end
        return value

    def chunks(self, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        self.seek(0)
        while self.tell() < self.length:
            yield self.read(min(chunk_size, self.length - self.tell()))


@dataclass(frozen=True)
class Partition:
    index: int
    start: int
    length: int
    type: str
    scheme: str
    name: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PartitionTable:
    scheme: str
    partitions: tuple[Partition, ...]
    metadata: dict[str, object]
    errors: tuple[str, ...] = ()


def parse_partition_table(path: Path, max_partitions: int = 32) -> PartitionTable | None:
    size = path.stat().st_size
    with path.open("rb") as stream:
        rdb = _parse_rdb(stream, size, max_partitions)
        if rdb is not None:
            return rdb
        return _parse_mbr(stream, size, max_partitions)


def _parse_mbr(stream: BinaryIO, size: int, max_partitions: int) -> PartitionTable | None:
    if size < 512:
        return None
    stream.seek(0)
    sector = stream.read(512)
    rows = [sector[446 + index * 16 : 462 + index * 16] for index in range(4)]
    populated = [row for row in rows if row[4] or any(row[8:16])]
    if not populated:
        return None
    plausible = [
        row
        for row in populated
        if row[0] in {0, 0x80}
        and row[4] != 0
        and struct.unpack_from("<I", row, 12)[0] != 0
    ]
    if not plausible:
        return None
    if sector[510:512] != b"\x55\xaa":
        raise PartitionTableError("MBR signature 0x55AA is absent")
    partitions: list[Partition] = []
    errors: list[str] = []
    for index, row in enumerate(rows):
        boot, type_code = row[0], row[4]
        lba_start, sectors = struct.unpack_from("<II", row, 8)
        if not type_code and not lba_start and not sectors:
            continue
        if boot not in {0, 0x80}:
            errors.append(f"MBR partition {index} has invalid boot flag 0x{boot:02x}")
            continue
        if type_code in {0x05, 0x0F, 0x85}:
            errors.append(f"MBR extended partition {index} is deferred")
            continue
        start, length = lba_start * 512, sectors * 512
        if not sectors or start < 512 or start > size or length > size - start:
            errors.append(f"MBR partition {index} lies outside image")
            continue
        partitions.append(
            Partition(
                index,
                start,
                length,
                f"0x{type_code:02X}",
                "MBR",
                metadata={
                    "partition.scheme": "MBR",
                    "partition.index": index,
                    "partition.start_bytes": start,
                    "partition.length_bytes": length,
                    "partition.type": f"0x{type_code:02X}",
                    "mbr.type_code": type_code,
                    "mbr.bootable": boot == 0x80,
                    "mbr.lba_start": lba_start,
                    "mbr.sector_count": sectors,
                },
            )
        )
    if len(partitions) > max_partitions:
        errors.append("partition count exceeds server maximum")
        partitions = partitions[:max_partitions]
    _mark_overlaps(partitions, errors)
    return PartitionTable(
        "MBR",
        tuple(partitions),
        {"mbr.signature": "55AA", "sector_size": 512},
        tuple(errors),
    )


def _be32(value: bytes, offset: int) -> int:
    return int(struct.unpack_from(">I", value, offset)[0])


def _valid_rdb_checksum(block: bytes) -> bool:
    if len(block) < 24:
        return False
    count = _be32(block, 4)
    if count < 6 or count > len(block) // 4:
        return False
    return bool(sum(struct.unpack(f">{count}I", block[: count * 4])) & 0xFFFFFFFF == 0)


def _parse_rdb(stream: BinaryIO, size: int, max_partitions: int) -> PartitionTable | None:
    probe_blocks = min(16, size // 512)
    rdb: bytes | None = None
    rdb_index = -1
    for index in range(probe_blocks):
        stream.seek(index * 512)
        candidate = stream.read(512)
        if candidate[:4] == b"RDSK":
            rdb, rdb_index = candidate, index
            break
    if rdb is None:
        return None
    if not _valid_rdb_checksum(rdb):
        raise PartitionTableError("invalid RDB checksum")
    block_size = _be32(rdb, 16)
    if block_size < 512 or block_size > 65536 or block_size & (block_size - 1):
        raise PartitionTableError("invalid RDB block size")
    pointer = _be32(rdb, 28)
    partitions: list[Partition] = []
    errors: list[str] = []
    seen: set[int] = set()
    while pointer != 0xFFFFFFFF:
        if pointer in seen:
            errors.append("RDB partition pointer cycle")
            break
        if len(seen) >= max_partitions:
            errors.append("partition count exceeds server maximum")
            break
        seen.add(pointer)
        offset = pointer * block_size
        if offset > size or block_size > size - offset:
            errors.append("RDB partition pointer lies outside image")
            break
        stream.seek(offset)
        block = stream.read(block_size)
        if block[:4] != b"PART" or not _valid_rdb_checksum(block):
            errors.append(f"invalid RDB PART block at {pointer}")
            break
        name_len = min(block[36], 31)
        name = block[37 : 37 + name_len].decode("latin-1", errors="replace") or None
        env = 128
        surfaces, blocks_per_track = _be32(block, env + 12), _be32(block, env + 20)
        low, high = _be32(block, env + 36), _be32(block, env + 40)
        dostype = block[env + 64 : env + 68]
        boot_priority = struct.unpack_from(">i", block, env + 60)[0]
        if not surfaces or not blocks_per_track or high < low:
            errors.append(f"RDB partition {len(partitions)} has invalid geometry")
        else:
            cylinder_bytes = surfaces * blocks_per_track * block_size
            start, length = low * cylinder_bytes, (high - low + 1) * cylinder_bytes
            if start > size or length > size - start:
                errors.append(f"RDB partition {len(partitions)} lies outside image")
            else:
                text_type = (
                    "DOS\\" + str(dostype[3]) if dostype[:3] == b"DOS" else dostype.hex().upper()
                )
                index = len(partitions)
                partitions.append(
                    Partition(
                        index,
                        start,
                        length,
                        text_type,
                        "RDB",
                        name,
                        {
                            "partition.scheme": "RDB",
                            "partition.index": index,
                            "partition.start_bytes": start,
                            "partition.length_bytes": length,
                            "partition.type": text_type,
                            "partition.name": name,
                            "rdb.dostype": text_type,
                            "rdb.low_cylinder": low,
                            "rdb.high_cylinder": high,
                            "rdb.block_size": block_size,
                            "rdb.surfaces": surfaces,
                            "rdb.blocks_per_track": blocks_per_track,
                            "rdb.boot_priority": boot_priority,
                        },
                    )
                )
        pointer = _be32(block, 16)
    _mark_overlaps(partitions, errors)
    return PartitionTable(
        "RDB",
        tuple(partitions),
        {
            "rdb.block_location": rdb_index,
            "rdb.block_size": block_size,
            "rdb.filesystem_handler_execution": False,
        },
        tuple(errors),
    )


def _mark_overlaps(partitions: list[Partition], errors: list[str]) -> None:
    ordered = sorted(partitions, key=lambda item: (item.start, item.length))
    for left, right in zip(ordered, ordered[1:], strict=False):
        if right.start < left.start + left.length:
            errors.append(f"OVERLAPPING_PARTITIONS: {left.index} and {right.index}")


def hash_range(path: Path, start: int, length: int) -> dict[str, str]:
    hashers: dict[str, Any] = {
        "sha256": hashlib.sha256(),
        "sha1": hashlib.sha1(),
        "md5": hashlib.md5(usedforsecurity=False),
    }
    try:
        import blake3

        hashers["blake3"] = blake3.blake3()
    except ImportError:  # pragma: no cover - production dependency is mandatory
        hashers["blake3"] = hashlib.blake2s()
    with path.open("rb") as stream:
        reader = BoundedRangeReader(stream, start, length, path.stat().st_size)
        for chunk in reader.chunks():
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}
