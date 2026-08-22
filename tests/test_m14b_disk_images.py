from __future__ import annotations

import hashlib
import io
import struct
import zipfile
from pathlib import Path

import pytest
from test_m14_containers import run_container

from avbox.analyzers.containers import ContainerAnalyzer
from avbox.analyzers.disk_images import DiskImageError, parse_disk_image


def _short_entry(name: str, cluster: int, size: int, *, directory: bool = False) -> bytes:
    row = bytearray(32)
    if name in {".", ".."}:
        row[:11] = name.encode("ascii").ljust(11)
    else:
        stem, _, suffix = name.partition(".")
        row[:8] = stem.upper().encode("ascii").ljust(8)
        row[8:11] = suffix.upper().encode("ascii").ljust(3)
    row[11] = 0x10 if directory else 0x20
    struct.pack_into("<H", row, 20, cluster >> 16)
    struct.pack_into("<H", row, 26, cluster & 0xFFFF)
    struct.pack_into("<I", row, 28, size)
    return bytes(row)


def make_fat(path: Path, variant: str = "FAT12") -> dict[str, bytes]:
    geometry = {
        "FAT12": (2880, 1, 2, 9, 224),
        "FAT16": (32768, 1, 2, 128, 512),
        "FAT32": (131072, 32, 2, 1009, 0),
    }
    sectors, reserved, fats, fat_sectors, root_count = geometry[variant]
    image = bytearray(sectors * 512)
    boot = image[:512]
    boot[:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"AVBOX14B"
    struct.pack_into("<H", boot, 11, 512)
    boot[13] = 1
    struct.pack_into("<H", boot, 14, reserved)
    boot[16] = fats
    struct.pack_into("<H", boot, 17, root_count)
    if sectors < 65536:
        struct.pack_into("<H", boot, 19, sectors)
    else:
        struct.pack_into("<I", boot, 32, sectors)
    boot[21] = 0xF0
    if variant == "FAT32":
        struct.pack_into("<I", boot, 36, fat_sectors)
        struct.pack_into("<I", boot, 44, 2)
        struct.pack_into("<HH", boot, 48, 1, 6)
        boot[66] = 0x29
        boot[71:82] = b"AVBOX14B   "
    else:
        struct.pack_into("<H", boot, 22, fat_sectors)
        boot[38] = 0x29
        boot[43:54] = b"AVBOX14B   "
    boot[510:512] = b"\x55\xaa"
    image[:512] = boot
    if variant == "FAT32":
        fsinfo = bytearray(512)
        struct.pack_into("<I", fsinfo, 0, 0x41615252)
        struct.pack_into("<I", fsinfo, 484, 0x61417272)
        struct.pack_into("<II", fsinfo, 488, 0xFFFFFFFF, 0xFFFFFFFF)
        fsinfo[510:512] = b"\x55\xaa"
        image[512:1024] = fsinfo
        image[6 * 512 : 7 * 512] = boot
    root_sectors = (root_count * 32 + 511) // 512
    first_data = reserved + fats * fat_sectors + root_sectors
    fat = bytearray(fat_sectors * 512)

    def set_fat(cluster: int, value: int) -> None:
        if variant == "FAT12":
            pos = cluster + cluster // 2
            current = int.from_bytes(fat[pos : pos + 2], "little")
            current = (
                (current & 0x000F) | (value << 4) if cluster & 1 else (current & 0xF000) | value
            )
            fat[pos : pos + 2] = current.to_bytes(2, "little")
        elif variant == "FAT16":
            struct.pack_into("<H", fat, cluster * 2, value)
        else:
            struct.pack_into("<I", fat, cluster * 4, value)

    eof = {"FAT12": 0xFFF, "FAT16": 0xFFFF, "FAT32": 0x0FFFFFFF}[variant]
    set_fat(0, eof)
    set_fat(1, eof)
    next_cluster = 2
    if variant == "FAT32":
        set_fat(2, eof)
        next_cluster = 3
    directory_cluster = next_cluster
    set_fat(directory_cluster, eof)
    next_cluster += 1
    nested_zip = io.BytesIO()
    with zipfile.ZipFile(nested_zip, "w") as archive:
        archive.writestr("inside.txt", b"nested from FAT\n")
    files = {
        "ROOT.TXT": b"root from FAT\n",
        "DUP1.BIN": b"duplicate\n",
        "DUP2.BIN": b"duplicate\n",
        "NEST.ZIP": nested_zip.getvalue(),
        "DIR/CHILD.TXT": b"child from FAT\n",
    }
    locations: dict[str, int] = {}
    for name, payload in files.items():
        cluster = next_cluster
        locations[name] = cluster
        chunks = max(1, (len(payload) + 511) // 512)
        for index in range(chunks):
            current = cluster + index
            set_fat(current, eof if index + 1 == chunks else current + 1)
            start = (first_data + (current - 2)) * 512
            image[start : start + 512] = payload[index * 512 : (index + 1) * 512].ljust(512, b"\0")
        next_cluster += chunks
    directory = bytearray(512)
    directory[:32] = _short_entry(".", directory_cluster, 0, directory=True)
    directory[32:64] = _short_entry("..", 0, 0, directory=True)
    directory[64:96] = _short_entry(
        "CHILD.TXT", locations["DIR/CHILD.TXT"], len(files["DIR/CHILD.TXT"])
    )
    start = (first_data + (directory_cluster - 2)) * 512
    image[start : start + 512] = directory
    root = bytearray(512 if variant == "FAT32" else root_sectors * 512)
    label_entry = bytearray(_short_entry("AVBOX14B", 0, 0))
    label_entry[11] = 0x08
    rows = [
        bytes(label_entry),
        _short_entry("ROOT.TXT", locations["ROOT.TXT"], len(files["ROOT.TXT"])),
        _short_entry("DIR", directory_cluster, 0, directory=True),
        _short_entry("DUP1.BIN", locations["DUP1.BIN"], len(files["DUP1.BIN"])),
        _short_entry("DUP2.BIN", locations["DUP2.BIN"], len(files["DUP2.BIN"])),
        _short_entry("NEST.ZIP", locations["NEST.ZIP"], len(files["NEST.ZIP"])),
    ]
    for index, row in enumerate(rows):
        root[index * 32 : (index + 1) * 32] = row
    root_sector = first_data if variant == "FAT32" else reserved + fats * fat_sectors
    image[root_sector * 512 : root_sector * 512 + len(root)] = root
    for index in range(fats):
        start = (reserved + index * fat_sectors) * 512
        image[start : start + len(fat)] = fat
    path.write_bytes(image)
    return files


def _checksum(block: bytearray) -> None:
    struct.pack_into(">I", block, 20, 0)
    values = struct.unpack(">128I", block)
    struct.pack_into(">I", block, 20, (-sum(values)) & 0xFFFFFFFF)


def _adf_hash(name: str) -> int:
    value = len(name)
    for char in name.upper().encode("latin-1"):
        value = (value * 13 + char) & 0x7FF
    return value % 72


def make_lh0(name: str, payload: bytes) -> bytes:
    encoded = name.encode("ascii")
    header_size = 22 + len(encoded)
    header = bytearray(header_size + 2)
    header[0] = header_size
    header[2:7] = b"-lh0-"
    struct.pack_into("<II", header, 7, len(payload), len(payload))
    header[19] = 0x20
    header[20] = 0
    header[21] = len(encoded)
    header[22 : 22 + len(encoded)] = encoded
    crc = 0
    for value in payload:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    struct.pack_into("<H", header, 22 + len(encoded), crc)
    header[1] = sum(header[2 : 2 + header_size]) & 0xFF
    return bytes(header) + payload + b"\0"


def make_adf(path: Path, filesystem: str = "OFS") -> dict[str, bytes]:
    image = bytearray(901120)
    image[:4] = b"DOS\x00" if filesystem == "OFS" else b"DOS\x01"
    root_key = 880
    free_key = 881
    entries: dict[str, bytes] = {
        "ROOT.TXT": b"root from ADF\n",
        "DUP1": b"duplicate\n",
        "DUP2": b"duplicate\n",
        "DRAWER/CHILD": b"child from ADF\n",
        "ARCHIVE.LHA": make_lh0("lha-child.txt", b"ADF LHA child\n"),
        # Split the marker across filesystem data blocks in raw media. The
        # extracted child is positive while direct disk/partition scans remain
        # distinct and clean.
        "YARA-MARKER": (b"A" * (480 if filesystem == "OFS" else 500))
        + b"AVBOX_M1_HARMLESS_POSITIVE_7F45D8\n",
    }

    def put_header(key: int, name: str, kind: int, parent: int, payload: bytes = b"") -> bytearray:
        nonlocal free_key
        header = bytearray(512)
        struct.pack_into(">I", header, 0, 2)
        struct.pack_into(">I", header, 4, key)
        header[432] = len(name)
        header[433 : 433 + len(name)] = name.encode("latin-1")
        struct.pack_into(">I", header, 500, parent)
        struct.pack_into(">i", header, 508, kind)
        if kind == -3:
            struct.pack_into(">I", header, 324, len(payload))
            chunks = max(
                1,
                (len(payload) + (487 if filesystem == "OFS" else 511))
                // (488 if filesystem == "OFS" else 512),
            )
            struct.pack_into(">I", header, 8, chunks)
            pointers: list[int] = []
            for index in range(chunks):
                data_key = free_key
                free_key += 1
                pointers.append(data_key)
                if name == "YARA-MARKER" and chunks > 1 and index == 0:
                    # An unused block prevents the marker split from remaining
                    # contiguous in raw disk bytes.
                    free_key += 1
                value = bytearray(512)
                chunk = payload[
                    index * (488 if filesystem == "OFS" else 512) : (index + 1)
                    * (488 if filesystem == "OFS" else 512)
                ]
                if filesystem == "OFS":
                    struct.pack_into(
                        ">IIIII",
                        value,
                        0,
                        8,
                        key,
                        index + 1,
                        len(chunk),
                        pointers[-1] + 1 if index + 1 < chunks else 0,
                    )
                    value[24 : 24 + len(chunk)] = chunk
                    _checksum(value)
                else:
                    value[: len(chunk)] = chunk
                image[data_key * 512 : (data_key + 1) * 512] = value
            for index, pointer in enumerate(pointers):
                struct.pack_into(">I", header, 308 - index * 4, pointer)
        return header

    root = bytearray(512)
    struct.pack_into(">I", root, 0, 2)
    struct.pack_into(">I", root, 12, 72)
    root[432:441] = b"\x08AVBOX14B"
    struct.pack_into(">i", root, 508, 1)
    drawer_key = free_key
    free_key += 1
    drawer = put_header(drawer_key, "DRAWER", 2, root_key)
    child_key = free_key
    free_key += 1
    child = put_header(child_key, "CHILD", -3, drawer_key, entries["DRAWER/CHILD"])
    struct.pack_into(">I", drawer, 24 + _adf_hash("CHILD") * 4, child_key)
    _checksum(child)
    _checksum(drawer)
    image[child_key * 512 : (child_key + 1) * 512] = child
    image[drawer_key * 512 : (drawer_key + 1) * 512] = drawer
    root_members: list[tuple[int, bytearray, str]] = [(drawer_key, drawer, "DRAWER")]
    for name in ("ROOT.TXT", "DUP1", "DUP2", "ARCHIVE.LHA", "YARA-MARKER"):
        key = free_key
        free_key += 1
        header = put_header(key, name, -3, root_key, entries[name])
        _checksum(header)
        image[key * 512 : (key + 1) * 512] = header
        root_members.append((key, header, name))
    for key, header, name in root_members:
        bucket = _adf_hash(name)
        previous = struct.unpack_from(">I", root, 24 + bucket * 4)[0]
        if previous:
            struct.pack_into(">I", header, 496, previous)
            _checksum(header)
            image[key * 512 : (key + 1) * 512] = header
        struct.pack_into(">I", root, 24 + bucket * 4, key)
    _checksum(root)
    image[root_key * 512 : (root_key + 1) * 512] = root
    path.write_bytes(image)
    return entries


@pytest.mark.parametrize("variant", ["FAT12", "FAT16", "FAT32"])
def test_fat_variants_enumerate_hash_and_duplicate(tmp_path: Path, variant: str) -> None:
    source = tmp_path / "opaque.bin"
    expected = make_fat(source, variant)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    image = parse_disk_image(source)
    assert image and image.filesystem == variant
    assert {entry.path: entry.data for entry in image.entries} == expected
    job = run_container(tmp_path, source, use_bubblewrap=False)
    assert all(edge.relationship == "FILESYSTEM_ENTRY_OF" for edge in job.relationships[:5])
    duplicate_hash = hashlib.sha256(b"duplicate\n").hexdigest()
    assert sum(edge.target_sha256 == duplicate_hash for edge in job.relationships) == 2
    nested_parent = next(
        item.object.sha256 for item in job.derived_objects if item.member_name == "NEST.ZIP"
    )
    assert any(
        item.member_name == "inside.txt" and item.depth == 2 and item.parent_sha256 == nested_parent
        for item in job.derived_objects
    )
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("filesystem", ["OFS", "FFS"])
def test_adf_variants_enumerate_nested_paths_and_hashes(tmp_path: Path, filesystem: str) -> None:
    source = tmp_path / "misleading.exe"
    expected = make_adf(source, filesystem)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    image = parse_disk_image(source)
    assert image and image.filesystem == filesystem
    assert {entry.path: entry.data for entry in image.entries} == expected
    job = run_container(tmp_path, source, use_bubblewrap=False)
    assert all(
        edge.relationship == "FILESYSTEM_ENTRY_OF" for edge in job.relationships if edge.depth == 1
    )
    assert {item.member_name for item in job.derived_objects if item.depth == 1} == set(expected)
    lha_parent = next(
        item.object.sha256 for item in job.derived_objects if item.member_name == "ARCHIVE.LHA"
    )
    assert any(
        item.member_name == "lha-child.txt" and item.depth == 2 and item.parent_sha256 == lha_parent
        for item in job.derived_objects
    )
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_disk_corruption_false_positive_and_global_budget(tmp_path: Path) -> None:
    source = tmp_path / "fat.img"
    make_fat(source)
    damaged = bytearray(source.read_bytes())
    damaged[512 + 4 : 512 + 6] = b"\x07\x00"
    source.write_bytes(damaged)
    with pytest.raises(DiskImageError):
        parse_disk_image(source)
    job = run_container(tmp_path, source)
    assert job.completeness == "PARTIAL_ERROR"
    assert job.normalized_verdict.value == "NOT_SCANNED"

    ordinary = tmp_path / "ordinary.bin"
    ordinary.write_bytes(b"DOS\0" + b"filesystem-like" + b"\0" * 1000)
    assert ContainerAnalyzer._kind(ordinary) is None

    make_fat(source)
    limited = run_container(tmp_path, source, max_total_children=5)
    assert len(limited.derived_objects) == 5
    assert limited.completeness == "PARTIAL_LIMIT"
    assert "TOTAL_CHILD_COUNT_LIMIT" in limited.extraction_usage.limit_events

    adf = tmp_path / "damaged.adf"
    make_adf(adf)
    damaged_adf = bytearray(adf.read_bytes())
    damaged_adf[880 * 512 + 24] ^= 1
    adf.write_bytes(damaged_adf)
    adf_job = run_container(tmp_path, adf)
    assert adf_job.completeness == "PARTIAL_ERROR"
    assert "CORRUPT_FILESYSTEM" in adf_job.extraction_usage.limit_events
    assert adf_job.normalized_verdict.value == "NOT_SCANNED"
