from __future__ import annotations

import struct
import time
from datetime import UTC, datetime
from pathlib import Path

from avbox.models import (
    AnalyzerResult,
    Assessment,
    Confidence,
    Finding,
    InputArtifact,
    Observation,
    QualificationState,
    ScannerClass,
    StructuralState,
    StructuralValidation,
)
from avbox.scanners.base import ProbeResult

from .disk_images import DiskImageError, parse_disk_image
from .generic import GenericAnalyzer
from .partitions import PartitionTableError, parse_partition_table

VERSION = "1.0.0"


class StructuralValidator(GenericAnalyzer):
    """Bounded, read-only preservation validator; it never emits a security verdict."""

    analyzer_id = "structural-validator"
    analyzer_class = ScannerClass.STRUCTURAL_VALIDATOR
    product = "AVBox Retro Media Structural Validator"

    def __init__(self, max_bytes: int = 256 * 1024 * 1024, max_nodes: int = 100_000):
        self.max_bytes = max_bytes
        self.max_nodes = max_nodes

    def probe(self) -> ProbeResult:
        return ProbeResult(
            True, "built-in read-only validators", QualificationState.PROBED, VERSION
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        del job_id
        started_at = datetime.now(UTC)
        started = time.monotonic()
        validation = self._validate(artifact, source, started)
        completed = datetime.now(UTC)
        if validation is None:
            return AnalyzerResult(
                analyzer_id=self.analyzer_id,
                analyzer_class=self.analyzer_class,
                product=self.product,
                implementation="avbox.analyzers.structural.StructuralValidator",
                product_version=VERSION,
                qualification_state=QualificationState.PROBED,
                started_at=started_at,
                completed_at=completed,
                duration_seconds=time.monotonic() - started,
                execution_profile="built-in-userspace-read-only-bounded",
                native_status="unsupported",
            )
        qualification = (
            QualificationState.QUALIFIED
            if validation is not None
            and validation.format in {"ADF", "FAT", "RDB/HDF", "ISO9660", "LHA"}
            and not (
                validation.variant
                and validation.variant
                in {"OFS_INTL", "FFS_INTL", "OFS_DIRCACHE", "FFS_DIRCACHE"}
            )
            else QualificationState.PROBED
        )
        return AnalyzerResult(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="avbox.analyzers.structural.StructuralValidator",
            product_version=VERSION,
            qualification_state=qualification,
            started_at=started_at,
            completed_at=completed,
            duration_seconds=time.monotonic() - started,
            execution_profile="built-in-userspace-read-only-bounded",
            native_status=validation.state.value.lower(),
            observations=validation.observations,
            findings=validation.findings,
            assessments=validation.assessments,
            structural_validation=validation,
        )

    def _validate(
        self, artifact: InputArtifact, source: Path, started: float
    ) -> StructuralValidation | None:
        size = source.stat().st_size
        with source.open("rb") as stream:
            head = stream.read(min(size, 65536))
        if head[:3] == b"DOS":
            if size > self.max_bytes:
                return self._result(
                    artifact,
                    "ADF",
                    None,
                    StructuralState.PARTIAL,
                    [],
                    ["VALIDATION_BYTE_LIMIT"],
                    started,
                    "PARTIAL_LIMIT",
                )
            return self._adf(artifact, source.read_bytes(), started)
        if len(head) >= 512 and head[510:512] == b"\x55\xaa" and _fat_bpb_plausible(head):
            if size > self.max_bytes:
                return self._result(
                    artifact,
                    "FAT",
                    None,
                    StructuralState.PARTIAL,
                    [],
                    ["VALIDATION_BYTE_LIMIT"],
                    started,
                    "PARTIAL_LIMIT",
                )
            return self._fat(artifact, source.read_bytes(), started)
        if any(head[i * 512 : i * 512 + 4] == b"RDSK" for i in range(min(16, len(head) // 512))):
            return self._rdb(artifact, source, started)
        if len(head) >= 0x8006 and head[0x8001:0x8006] == b"CD001":
            return self._iso(artifact, source, started)
        if len(head) >= 22 and head[2:7] == b"-lh0-":
            if size > self.max_bytes:
                return self._result(
                    artifact,
                    "LHA",
                    "-lh0-",
                    StructuralState.PARTIAL,
                    [],
                    ["VALIDATION_BYTE_LIMIT"],
                    started,
                    "PARTIAL_LIMIT",
                )
            return self._lha(artifact, source.read_bytes(), started)
        return None

    def _adf(self, artifact: InputArtifact, data: bytes, started: float) -> StructuralValidation:
        findings: list[str] = []
        observations: list[tuple[str, object]] = []
        size_valid = len(data) == 901120
        observations.append(("ADF_SIZE_VALID", size_valid))
        if not size_valid:
            findings.append(
                "ADF_IMAGE_TRUNCATED" if len(data) < 901120 else "ADF_NON_STANDARD_SIZE"
            )
        variant = {
            0: "OFS",
            1: "FFS",
            2: "OFS_INTL",
            3: "FFS_INTL",
            4: "OFS_DIRCACHE",
            5: "FFS_DIRCACHE",
        }.get(data[3] if len(data) > 3 else -1)
        observations.append(("ADF_DOSTYPE", f"DOS\\{data[3]}" if len(data) > 3 else None))
        boot_valid = len(data) >= 1024 and _amiga_boot_checksum(data[:1024])
        observations.append(("ADF_BOOTBLOCK_CHECKSUM_VALID", boot_valid))
        if not boot_valid:
            findings.append("BOOTBLOCK_CHECKSUM_MISMATCH")
        if not size_valid or variant not in {"OFS", "FFS"}:
            state = (
                StructuralState.TRUNCATED if len(data) < 901120 else StructuralState.NON_STANDARD
            )
            return self._result(artifact, "ADF", variant, state, observations, findings, started)
        root = data[880 * 512 : 881 * 512]
        root_valid = _be32(root, 0) == 2 and _sbe32(root, 508) == 1 and _block_checksum(root)
        observations.append(("ADF_ROOTBLOCK_CHECKSUM_VALID", root_valid))
        if not root_valid:
            findings.append("ROOTBLOCK_CHECKSUM_MISMATCH")
        bitmap_valid = True
        bitmap_keys = [_be32(root, pos) for pos in range(316, 412, 4) if _be32(root, pos)]
        for key in bitmap_keys:
            if key >= 1760:
                bitmap_valid = False
                findings.append("ADF_BLOCK_REFERENCE_OUT_OF_RANGE")
            elif not _block_checksum(data[key * 512 : (key + 1) * 512]):
                bitmap_valid = False
                findings.append("ADF_BITMAP_CHECKSUM_MISMATCH")
        observations.append(("ADF_BITMAP_VALID", bitmap_valid))
        reference_valid = True
        try:
            parse_disk_image_bytes = parse_disk_image  # keep parser and validator behavior aligned
            del parse_disk_image_bytes
            # The enumeration parser performs bounded directory/file chain, loop, OFS data,
            # header checksum, and range checks. Use an ephemeral path-free equivalent below.
            self._walk_adf(data, variant)
        except DiskImageError as exc:
            reference_valid = False
            message = str(exc).lower()
            if "cyclic" in message:
                findings.append("ADF_CHAIN_LOOP")
            elif "outside" in message:
                findings.append("ADF_BLOCK_REFERENCE_OUT_OF_RANGE")
            elif "truncated" in message:
                findings.append("ADF_DATA_CHAIN_TRUNCATED")
            else:
                findings.append("ADF_BLOCK_STRUCTURE_INVALID")
        observations.append(("ADF_BLOCK_REFERENCE_VALID", reference_valid))
        state = StructuralState.VALID if not findings else StructuralState.DAMAGED
        return self._result(artifact, "ADF", variant, state, observations, findings, started)

    def _walk_adf(self, data: bytes, variant: str) -> None:
        blocks = len(data) // 512
        seen: set[int] = {880}
        nodes = 0

        def block(key: int) -> bytes:
            if key < 2 or key >= blocks:
                raise DiskImageError("ADF block pointer lies outside image")
            return data[key * 512 : (key + 1) * 512]

        def walk(directory: bytes) -> None:
            nonlocal nodes
            for pos in range(24, 312, 4):
                key = _be32(directory, pos)
                chain: set[int] = set()
                while key:
                    nodes += 1
                    if nodes > self.max_nodes:
                        raise DiskImageError("ADF validation node limit")
                    if key in chain or key in seen:
                        raise DiskImageError("cyclic ADF directory hash chain")
                    chain.add(key)
                    seen.add(key)
                    header = block(key)
                    if _be32(header, 0) != 2 or not _block_checksum(header):
                        raise DiskImageError("invalid ADF entry header")
                    kind = _sbe32(header, 508)
                    if kind == 2:
                        walk(header)
                    elif kind == -3:
                        wanted = _be32(header, 324)
                        total = 0
                        data_seen: set[int] = set()
                        for pointer_pos in range(308, 20, -4):
                            pointer = _be32(header, pointer_pos)
                            if not pointer:
                                continue
                            if pointer in data_seen or pointer in seen:
                                raise DiskImageError("cyclic ADF file block list")
                            data_seen.add(pointer)
                            seen.add(pointer)
                            payload = block(pointer)
                            if variant == "OFS":
                                count = _be32(payload, 12)
                                if (
                                    _be32(payload, 0) != 8
                                    or _be32(payload, 4) != key
                                    or count > 488
                                    or not _block_checksum(payload)
                                ):
                                    raise DiskImageError("invalid OFS data block")
                                total += count
                            else:
                                total += 512
                            if total >= wanted:
                                break
                        if total < wanted:
                            raise DiskImageError("truncated ADF file")
                    key = _be32(header, 496)

        walk(block(880))

    def _fat(self, artifact: InputArtifact, data: bytes, started: float) -> StructuralValidation:
        findings: list[str] = []
        observations: list[tuple[str, object]] = []
        bps, spc, reserved, copies = _le16(data, 11), data[13], _le16(data, 14), data[16]
        roots, total = _le16(data, 17), _le16(data, 19) or _le32(data, 32)
        fat_size = _le16(data, 22) or _le32(data, 36)
        root_sectors = (roots * 32 + bps - 1) // bps if bps else 0
        first_data = reserved + copies * fat_size + root_sectors
        clusters = (total - first_data) // spc if spc and total >= first_data else 0
        variant = "FAT12" if clusters < 4085 else "FAT16" if clusters < 65525 else "FAT32"
        bpb_valid = (
            bps in {512, 1024, 2048, 4096}
            and spc > 0
            and not spc & (spc - 1)
            and reserved > 0
            and copies in {1, 2}
            and total > first_data
            and total * bps <= len(data)
            and fat_size > 0
        )
        observations.extend([("FAT_BPB_VALID", bpb_valid), ("FAT_VARIANT", variant)])
        if not bpb_valid:
            findings.append("FAT_BPB_INCONSISTENT")
            state = (
                StructuralState.TRUNCATED
                if total * max(bps, 1) > len(data)
                else StructuralState.CORRUPT
            )
            return self._result(artifact, "FAT", variant, state, observations, findings, started)
        fats = [
            data[(reserved + i * fat_size) * bps : (reserved + (i + 1) * fat_size) * bps]
            for i in range(copies)
        ]
        copies_valid = len(fats) < 2 or fats[0] == fats[1]
        observations.append(("FAT_COPIES_CONSISTENT", copies_valid))
        if not copies_valid:
            findings.append("FAT_COPIES_MISMATCH")
        used: dict[int, str] = {}
        allocated = {c for c in range(2, clusters + 2) if _fat_value(fats[0], c, variant) != 0}
        reachable: set[int] = set()
        root_start = (reserved + copies * fat_size) * bps
        root = (
            self._fat_chain(
                data,
                fats[0],
                _le32(data, 44),
                variant,
                first_data,
                spc,
                bps,
                clusters,
                used,
                reachable,
                "<root>",
                findings,
            )
            if variant == "FAT32"
            else data[root_start : root_start + root_sectors * bps]
        )
        self._fat_directory(
            data,
            root,
            fats[0],
            variant,
            first_data,
            spc,
            bps,
            clusters,
            used,
            reachable,
            findings,
            set(),
            "",
        )
        orphans = allocated - reachable - ({2} if variant == "FAT32" else set())
        observations.extend(
            [
                ("FAT_CHAIN_VALID", not any("CHAIN" in f or "CLUSTER" in f for f in findings)),
                ("FAT_ORPHAN_CLUSTERS", len(orphans)),
            ]
        )
        if orphans:
            findings.append("FAT_ORPHAN_CLUSTERS_PRESENT")
        state = StructuralState.VALID if not findings else StructuralState.DAMAGED
        return self._result(artifact, "FAT", variant, state, observations, findings, started)

    def _fat_chain(
        self,
        data: bytes,
        fat: bytes,
        start: int,
        variant: str,
        first_data: int,
        spc: int,
        bps: int,
        clusters: int,
        used: dict[int, str],
        reachable: set[int],
        owner: str,
        findings: list[str],
        wanted: int | None = None,
    ) -> bytes:
        out = bytearray()
        seen: set[int] = set()
        current = start
        while current >= 2:
            if current in seen:
                findings.append("FAT_CLUSTER_CHAIN_LOOP")
                break
            if current >= clusters + 2:
                findings.append("FAT_CLUSTER_OUT_OF_RANGE")
                break
            if current in used and used[current] != owner:
                findings.append("FAT_CROSSLINK_DETECTED")
                break
            seen.add(current)
            reachable.add(current)
            used[current] = owner
            offset = (first_data + (current - 2) * spc) * bps
            out.extend(data[offset : offset + spc * bps])
            value = _fat_value(fat, current, variant)
            eof = value >= {"FAT12": 0xFF8, "FAT16": 0xFFF8, "FAT32": 0x0FFFFFF8}[variant]
            if eof:
                break
            if value < 2 or value >= clusters + 2:
                findings.append("FAT_CLUSTER_REFERENCE_INVALID")
                break
            current = value
            if len(seen) > self.max_nodes:
                findings.append("FAT_CHAIN_LIMIT")
                break
        if wanted is not None and len(out) < wanted:
            findings.append("FAT_FILE_CHAIN_TRUNCATED")
        return bytes(out if wanted is None else out[:wanted])

    def _fat_directory(
        self,
        data: bytes,
        directory: bytes,
        fat: bytes,
        variant: str,
        first_data: int,
        spc: int,
        bps: int,
        clusters: int,
        used: dict[int, str],
        reachable: set[int],
        findings: list[str],
        dirs: set[int],
        prefix: str,
    ) -> None:
        for pos in range(0, min(len(directory), self.max_nodes * 32) - 31, 32):
            row = directory[pos : pos + 32]
            if row[0] == 0:
                break
            if row[0] == 0xE5 or row[11] == 0x0F or row[11] & 0x08:
                continue
            name = row[:11].decode("ascii", "replace").strip()
            if name in {".", ".."}:
                continue
            start = _le16(row, 26) | (_le16(row, 20) << 16)
            owner = f"{prefix}/{name}"
            if row[11] & 0x10:
                if start in dirs:
                    findings.append("FAT_DIRECTORY_LOOP")
                    continue
                dirs.add(start)
                child = self._fat_chain(
                    data,
                    fat,
                    start,
                    variant,
                    first_data,
                    spc,
                    bps,
                    clusters,
                    used,
                    reachable,
                    owner,
                    findings,
                )
                self._fat_directory(
                    data,
                    child,
                    fat,
                    variant,
                    first_data,
                    spc,
                    bps,
                    clusters,
                    used,
                    reachable,
                    findings,
                    dirs,
                    owner,
                )
            else:
                size = _le32(row, 28)
                self._fat_chain(
                    data,
                    fat,
                    start,
                    variant,
                    first_data,
                    spc,
                    bps,
                    clusters,
                    used,
                    reachable,
                    owner,
                    findings,
                    size,
                )

    def _rdb(self, artifact: InputArtifact, source: Path, started: float) -> StructuralValidation:
        findings: list[str] = []
        observations: list[tuple[str, object]] = [
            ("RDB_FILESYSTEM_CODE_EXECUTION", False),
            ("RDB_EMBEDDED_FILESYSTEM_CODE", "DATA_ONLY"),
        ]
        try:
            table = parse_partition_table(source, 256)
            if table is None:
                findings.append("RDB_IDENTIFIER_INVALID")
            else:
                observations.append(("RDB_CHECKSUM_VALID", True))
                for error in table.errors:
                    findings.append(_rdb_finding(error))
        except PartitionTableError as exc:
            observations.append(("RDB_CHECKSUM_VALID", False))
            findings.append(
                "RDB_CHECKSUM_MISMATCH"
                if "checksum" in str(exc).lower()
                else "RDB_STRUCTURE_INVALID"
            )
        state = StructuralState.VALID if not findings else StructuralState.DAMAGED
        return self._result(artifact, "RDB/HDF", "RDB", state, observations, findings, started)

    def _iso(self, artifact: InputArtifact, source: Path, started: float) -> StructuralValidation:
        findings: list[str] = []
        observations: list[tuple[str, object]] = []
        size = source.stat().st_size
        descriptors = 0
        pvd: bytes | None = None
        terminator = False
        with source.open("rb") as stream:
            for sector in range(16, min(size // 2048, 16 + 128)):
                stream.seek(sector * 2048)
                block = stream.read(2048)
                if len(block) != 2048:
                    findings.append("ISO_TRUNCATED_DESCRIPTOR")
                    break
                if block[1:6] != b"CD001" or block[6] != 1:
                    findings.append("ISO_VOLUME_DESCRIPTOR_INVALID")
                    break
                descriptors += 1
                if block[0] == 1:
                    pvd = block
                if block[0] == 255:
                    terminator = True
                    break
        observations.extend(
            [
                ("ISO_PVD_VALID", pvd is not None),
                ("ISO_DESCRIPTOR_TERMINATOR_PRESENT", terminator),
                ("ISO_DESCRIPTOR_COUNT", descriptors),
            ]
        )
        if pvd is None:
            findings.append("ISO_PRIMARY_VOLUME_DESCRIPTOR_MISSING")
        if not terminator:
            findings.append("ISO_DESCRIPTOR_TERMINATOR_MISSING")
        if pvd is not None:
            block_size = _le16(pvd, 128)
            volume_blocks = _le32(pvd, 80)
            observations.append(("ISO_LOGICAL_BLOCK_SIZE", block_size))
            if block_size != 2048:
                findings.append("ISO_LOGICAL_BLOCK_SIZE_INVALID")
            if volume_blocks * max(block_size, 1) > size:
                findings.append("ISO_VOLUME_SPACE_OUT_OF_RANGE")
            self._iso_directories(source, pvd[156:190], block_size, size, findings)
        state = (
            StructuralState.TRUNCATED
            if any("TRUNCATED" in f for f in findings)
            else StructuralState.VALID
            if not findings
            else StructuralState.DAMAGED
        )
        return self._result(artifact, "ISO9660", "base", state, observations, findings, started)

    def _iso_directories(
        self, source: Path, root: bytes, block_size: int, size: int, findings: list[str]
    ) -> None:
        pending = [root]
        seen: set[tuple[int, int]] = set()
        nodes = 0
        with source.open("rb") as stream:
            while pending and nodes < self.max_nodes:
                record = pending.pop()
                extent, length = _le32(record, 2), _le32(record, 10)
                key = (extent, length)
                if key in seen:
                    continue
                seen.add(key)
                offset = extent * block_size
                if offset > size or length > size - offset:
                    findings.append("ISO_DIRECTORY_EXTENT_OUT_OF_RANGE")
                    continue
                stream.seek(offset)
                directory = stream.read(length)
                pos = 0
                while pos < len(directory):
                    nodes += 1
                    row_len = directory[pos]
                    if row_len == 0:
                        pos = ((pos // block_size) + 1) * block_size
                        continue
                    if row_len < 34 or pos + row_len > len(directory):
                        findings.append("ISO_DIRECTORY_RECORD_MALFORMED")
                        break
                    row = directory[pos : pos + row_len]
                    child_extent = _le32(row, 2)
                    child_length = _le32(row, 10)
                    name_len = row[32]
                    if 33 + name_len > row_len:
                        findings.append("ISO_DIRECTORY_RECORD_MALFORMED")
                        break
                    if (
                        child_extent * block_size > size
                        or child_length > size - child_extent * block_size
                    ):
                        findings.append("ISO_FILE_EXTENT_OUT_OF_RANGE")
                    if row[25] & 2 and row[33 : 33 + name_len] not in {b"\0", b"\1"}:
                        pending.append(row)
                    pos += row_len
        if pending or nodes >= self.max_nodes:
            findings.append("ISO_DIRECTORY_NODE_LIMIT")

    def _lha(self, artifact: InputArtifact, data: bytes, started: float) -> StructuralValidation:
        findings: list[str] = []
        observations: list[tuple[str, object]] = []
        pos = 0
        members = 0
        while pos < len(data) and data[pos] != 0 and members < self.max_nodes:
            if pos + 22 > len(data):
                findings.append("LHA_ARCHIVE_TRUNCATED")
                break
            header_size = data[pos]
            end = pos + header_size + 2
            if header_size < 22 or end > len(data):
                findings.append("LHA_HEADER_MALFORMED")
                break
            header = data[pos:end]
            method = header[2:7].decode("ascii", "replace")
            observations.append((f"LHA_MEMBER_{members}_METHOD", method))
            if method != "-lh0-":
                findings.append("LHA_METHOD_UNSUPPORTED")
                break
            if sum(header[2 : 2 + header_size]) & 0xFF != header[1]:
                findings.append("LHA_HEADER_CHECKSUM_MISMATCH")
            packed = _le32(header, 7)
            name_len = header[21]
            crc_pos = 22 + name_len
            if crc_pos + 2 > len(header):
                findings.append("LHA_HEADER_MALFORMED")
                break
            payload_start, payload_end = end, end + packed
            if payload_end > len(data):
                findings.append("LHA_ARCHIVE_TRUNCATED")
                break
            if _crc16(data[payload_start:payload_end]) != _le16(header, crc_pos):
                findings.append("LHA_MEMBER_CRC_MISMATCH")
            members += 1
            pos = payload_end
        observations.append(("LHA_MEMBER_COUNT", members))
        state = (
            StructuralState.TRUNCATED
            if "LHA_ARCHIVE_TRUNCATED" in findings
            else (StructuralState.VALID if not findings else StructuralState.DAMAGED)
        )
        return self._result(artifact, "LHA", "-lh0-", state, observations, findings, started)

    def _result(
        self,
        artifact: InputArtifact,
        fmt: str,
        variant: str | None,
        state: StructuralState,
        observations: list[tuple[str, object]],
        findings: list[str],
        started: float,
        completeness: str = "COMPLETE",
    ) -> StructuralValidation:
        now = datetime.now(UTC)
        obs = [
            Observation(
                observation_type=k,
                value=v,
                analyzer_id=self.analyzer_id,
                source="read-only-validator",
                observed_at=now,
                confidence="exact",
            )
            for k, v in observations
        ]
        unique = list(dict.fromkeys(findings))
        fs = [
            Finding(
                finding_type=value,
                analyzer_id=self.analyzer_id,
                evidence_refs=[item.observation_type for item in obs],
            )
            for value in unique
        ]
        assessments = (
            []
            if state == StructuralState.VALID
            else [
                Assessment(
                    assessment_type="MEDIA_STRUCTURALLY_DAMAGED",
                    analyzer_id=self.analyzer_id,
                    statement=f"{fmt} structural validation state is {state.value}",
                    confidence=Confidence.HIGH,
                    evidence_refs=unique,
                )
            ]
        )
        return StructuralValidation(
            validator=self.analyzer_id,
            format=fmt,
            variant=variant,
            state=state,
            observations=obs,
            findings=fs,
            assessments=assessments,
            completeness=completeness,
            source_sha256=artifact.hashes.sha256,
            validator_version=VERSION,
            duration_seconds=time.monotonic() - started,
            limit_state="VALIDATION_BYTE_LIMIT" if completeness == "PARTIAL_LIMIT" else None,
        )


def _le16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _le32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _be32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def _sbe32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big", signed=True)


def _block_checksum(block: bytes) -> bool:
    return len(block) == 512 and sum(struct.unpack(">128I", block)) & 0xFFFFFFFF == 0


def _amiga_boot_checksum(block: bytes) -> bool:
    if len(block) != 1024:
        return False
    total = 0
    for value in struct.unpack(">256I", block):
        previous = total
        total = (total + value) & 0xFFFFFFFF
        if total < previous:
            total = (total + 1) & 0xFFFFFFFF
    return total == 0xFFFFFFFF


def _fat_bpb_plausible(data: bytes) -> bool:
    return len(data) >= 512 and _le16(data, 11) in {512, 1024, 2048, 4096} and data[13] != 0


def _fat_value(fat: bytes, cluster: int, variant: str) -> int:
    if variant == "FAT12":
        pos = cluster + cluster // 2
        if pos + 2 > len(fat):
            return 1
        value = _le16(fat, pos)
        return value >> 4 if cluster & 1 else value & 0xFFF
    width = 2 if variant == "FAT16" else 4
    pos = cluster * width
    if pos + width > len(fat):
        return 1
    value = int.from_bytes(fat[pos : pos + width], "little")
    return value if variant == "FAT16" else value & 0x0FFFFFFF


def _crc16(data: bytes) -> int:
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def _rdb_finding(error: str) -> str:
    lower = error.lower()
    if "cycle" in lower:
        return "RDB_POINTER_CYCLE"
    if "overlap" in lower:
        return "RDB_PARTITION_OVERLAP"
    if "outside" in lower:
        return "RDB_POINTER_OR_PARTITION_OUT_OF_RANGE"
    if "part block" in lower:
        return "RDB_PART_CHECKSUM_OR_STRUCTURE_INVALID"
    if "geometry" in lower:
        return "RDB_PARTITION_GEOMETRY_INVALID"
    return "RDB_STRUCTURE_WARNING"
