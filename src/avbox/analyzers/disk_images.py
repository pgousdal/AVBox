from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


class DiskImageError(ValueError):
    """A structurally invalid or damaged supported disk image."""


@dataclass(frozen=True)
class DiskEntry:
    path: str
    data: bytes
    index: int
    entry_type: str = "file"


@dataclass(frozen=True)
class DiskImage:
    format: str
    filesystem: str
    entries: tuple[DiskEntry, ...]
    metadata: dict[str, object]


def parse_disk_image(path: Path) -> DiskImage | None:
    """Recognize and enumerate the deliberately narrow M1.4b image set."""
    data = path.read_bytes()
    fat = _parse_fat(data)
    if fat is not None:
        return fat
    return _parse_adf(data)


def _u16(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def _parse_fat(data: bytes) -> DiskImage | None:
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return None
    bps = _u16(data, 11)
    spc = data[13]
    reserved = _u16(data, 14)
    fats = data[16]
    root_entries = _u16(data, 17)
    total = _u16(data, 19) or _u32(data, 32)
    fat_size = _u16(data, 22) or _u32(data, 36)
    if (
        bps not in {512, 1024, 2048, 4096}
        or not spc
        or spc & (spc - 1)
        or not reserved
        or fats not in {1, 2}
        or not total
        or not fat_size
        or total * bps > len(data)
    ):
        return None
    root_sectors = (root_entries * 32 + bps - 1) // bps
    first_data = reserved + fats * fat_size + root_sectors
    if first_data >= total:
        return None
    clusters = (total - first_data) // spc
    variant = "FAT12" if clusters < 4085 else "FAT16" if clusters < 65525 else "FAT32"
    if variant == "FAT32" and (root_entries != 0 or _u32(data, 44) < 2):
        return None
    fat_offset = reserved * bps
    fat_bytes = data[fat_offset : fat_offset + fat_size * bps]
    cluster_size = spc * bps

    def next_cluster(cluster: int) -> int | None:
        if variant == "FAT12":
            pos = cluster + cluster // 2
            if pos + 2 > len(fat_bytes):
                raise DiskImageError("FAT12 entry lies outside the FAT")
            value = int.from_bytes(fat_bytes[pos : pos + 2], "little")
            value = value >> 4 if cluster & 1 else value & 0xFFF
            eof = value >= 0xFF8
        elif variant == "FAT16":
            pos = cluster * 2
            if pos + 2 > len(fat_bytes):
                raise DiskImageError("FAT16 entry lies outside the FAT")
            value = _u16(fat_bytes, pos)
            eof = value >= 0xFFF8
        else:
            pos = cluster * 4
            if pos + 4 > len(fat_bytes):
                raise DiskImageError("FAT32 entry lies outside the FAT")
            value = _u32(fat_bytes, pos) & 0x0FFFFFFF
            eof = value >= 0x0FFFFFF8
        if eof:
            return None
        if value < 2 or value >= clusters + 2:
            raise DiskImageError("invalid FAT cluster chain")
        return value

    def cluster_data(cluster: int) -> bytes:
        sector = first_data + (cluster - 2) * spc
        start = sector * bps
        end = start + cluster_size
        if cluster < 2 or end > len(data):
            raise DiskImageError("cluster lies outside image")
        return data[start:end]

    def chain(start: int, wanted: int | None = None) -> bytes:
        if start < 2:
            if wanted:
                raise DiskImageError("missing cluster")
            return b""
        out = bytearray()
        seen: set[int] = set()
        current: int | None = start
        while current is not None:
            if current in seen or len(seen) > clusters:
                raise DiskImageError("cyclic FAT cluster chain")
            seen.add(current)
            out.extend(cluster_data(current))
            if wanted is not None and len(out) >= wanted:
                return bytes(out[:wanted])
            current = next_cluster(current)
        if wanted is not None and len(out) < wanted:
            raise DiskImageError("truncated FAT file")
        return bytes(out if wanted is None else out[:wanted])

    root_start = (reserved + fats * fat_size) * bps
    root = (
        chain(_u32(data, 44))
        if variant == "FAT32"
        else data[root_start : root_start + root_sectors * bps]
    )
    entries: list[DiskEntry] = []
    visited_dirs: set[int] = set()

    def walk(directory: bytes, prefix: str) -> None:
        long_parts: list[str] = []
        for offset in range(0, len(directory) - 31, 32):
            row = directory[offset : offset + 32]
            if row[0] == 0:
                break
            if row[0] == 0xE5:
                long_parts.clear()
                continue
            attr = row[11]
            if attr == 0x0F:
                raw = row[1:11] + row[14:26] + row[28:32]
                part = raw.decode("utf-16le", errors="replace").rstrip("\uffff\x00")
                long_parts.insert(0, part)
                continue
            if attr & 0x08:
                long_parts.clear()
                continue
            stem = row[:8].decode("cp437", errors="replace").rstrip()
            ext = row[8:11].decode("cp437", errors="replace").rstrip()
            short = stem + (("." + ext) if ext else "")
            name = "".join(long_parts) if long_parts else short
            long_parts.clear()
            if name in {".", ".."} or not name:
                continue
            logical = f"{prefix}/{name}" if prefix else name
            start = _u16(row, 26) | (_u16(row, 20) << 16)
            if attr & 0x10:
                if start in visited_dirs:
                    continue
                visited_dirs.add(start)
                walk(chain(start), logical)
            else:
                size = _u32(row, 28)
                entries.append(DiskEntry(logical, chain(start, size), len(entries)))

    walk(root, "")
    label_raw = data[71:82] if variant == "FAT32" else data[43:54]
    label = label_raw.decode("ascii", errors="replace").strip() or None
    return DiskImage(
        "raw-fat-image",
        variant,
        tuple(entries),
        {
            "disk_image_format": "raw-fat-image",
            "filesystem_type": variant,
            "filesystem_label": label,
            "filesystem_size": total * bps,
            "allocation_size": cluster_size,
            "image_byte_size": len(data),
            "root_entry_count": root_entries if variant != "FAT32" else None,
        },
    )


def _be32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from(">I", data, offset)[0])


def _signed_be32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from(">i", data, offset)[0])


def _parse_adf(data: bytes) -> DiskImage | None:
    # M1.4b deliberately recognizes only standard, unpartitioned 880 KiB ADF.
    if len(data) != 901120 or data[:3] != b"DOS" or data[3] not in {0, 1}:
        return None
    block_size = 512
    blocks = len(data) // block_size
    root_key = blocks // 2

    def block(key: int) -> bytes:
        if key < 2 or key >= blocks:
            raise DiskImageError("ADF block pointer lies outside image")
        return data[key * block_size : (key + 1) * block_size]

    def valid_checksum(value: bytes) -> bool:
        return bool(sum(struct.unpack(">128I", value)) & 0xFFFFFFFF == 0)

    root = block(root_key)
    if _be32(root, 0) != 2 or _signed_be32(root, 508) != 1 or not valid_checksum(root):
        return None
    dos_type = data[3]
    filesystem = "OFS" if dos_type == 0 else "FFS"
    entries: list[DiskEntry] = []
    visited: set[int] = {root_key}

    def bstr(value: bytes, offset: int) -> str:
        length = value[offset]
        if length > 107 or offset + 1 + length > len(value):
            raise DiskImageError("invalid ADF counted string")
        return value[offset + 1 : offset + 1 + length].decode("latin-1")

    def file_data(header: bytes, header_key: int) -> bytes:
        size = _be32(header, 324)
        pointers = [_be32(header, pos) for pos in range(24, 312, 4)]
        pointers = [value for value in reversed(pointers) if value]
        out = bytearray()
        seen: set[int] = set()
        for key in pointers:
            if key in seen:
                raise DiskImageError("cyclic ADF file block list")
            seen.add(key)
            value = block(key)
            if filesystem == "OFS":
                if _be32(value, 0) != 8 or _be32(value, 4) != header_key:
                    raise DiskImageError("invalid OFS data block")
                count = _be32(value, 12)
                if count > 488 or not valid_checksum(value):
                    raise DiskImageError("invalid OFS data block size/checksum")
                out.extend(value[24 : 24 + count])
            else:
                out.extend(value)
            if len(out) >= size:
                return bytes(out[:size])
        if len(out) != size:
            raise DiskImageError("truncated ADF file")
        return bytes(out)

    def walk_directory(directory: bytes, prefix: str) -> None:
        for bucket in range(72):
            key = _be32(directory, 24 + bucket * 4)
            chain_seen: set[int] = set()
            while key:
                if key in chain_seen or key in visited:
                    raise DiskImageError("cyclic ADF directory hash chain")
                chain_seen.add(key)
                visited.add(key)
                header = block(key)
                if _be32(header, 0) != 2 or not valid_checksum(header):
                    raise DiskImageError("invalid ADF entry header")
                kind = _signed_be32(header, 508)
                name = bstr(header, 432)
                if not name or "/" in name or "\\" in name or name in {".", ".."}:
                    raise DiskImageError("unsafe ADF entry name")
                logical = f"{prefix}/{name}" if prefix else name
                if kind == 2:
                    walk_directory(header, logical)
                elif kind == -3:
                    entries.append(DiskEntry(logical, file_data(header, key), len(entries)))
                else:
                    raise DiskImageError("unsupported ADF entry type")
                key = _be32(header, 496)

    walk_directory(root, "")
    volume = bstr(root, 432)
    return DiskImage(
        "amiga-adf",
        filesystem,
        tuple(entries),
        {
            "disk_image_format": "amiga-adf",
            "filesystem_type": filesystem,
            "dos_type": f"DOS\\{dos_type}",
            "filesystem_label": volume or None,
            "filesystem_size": len(data),
            "allocation_size": block_size,
            "image_byte_size": len(data),
        },
    )
