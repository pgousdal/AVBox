from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from avbox.analyzers.generic import GenericAnalyzer
from avbox.models import (
    AnalyzerResult,
    Assessment,
    Confidence,
    InputArtifact,
    Observation,
    QualificationState,
    ScannerClass,
)
from avbox.scanners.base import ProbeResult


class ExecutableError(ValueError):
    """Recognized executable structure is truncated, invalid, or over a bound."""


MAX_HEADERS = 4096
MAX_SECTIONS = 1024
MAX_SYMBOLS = 100_000
MAX_IMPORTS = 16_384
MAX_NAME = 4096

PE_MACHINES = {0x014C: "I386", 0x8664: "AMD64", 0x01C0: "ARM", 0xAA64: "ARM64"}
ELF_MACHINES = {3: "I386", 8: "MIPS", 20: "PPC", 40: "ARM", 62: "X86_64", 183: "AARCH64"}
HUNK_TYPES = {
    0x3E7: "HUNK_UNIT",
    0x3E8: "HUNK_NAME",
    0x3E9: "HUNK_CODE",
    0x3EA: "HUNK_DATA",
    0x3EB: "HUNK_BSS",
    0x3EC: "HUNK_RELOC32",
    0x3ED: "HUNK_RELOC16",
    0x3EE: "HUNK_RELOC8",
    0x3EF: "HUNK_EXT",
    0x3F0: "HUNK_SYMBOL",
    0x3F1: "HUNK_DEBUG",
    0x3F2: "HUNK_END",
    0x3F3: "HUNK_HEADER",
    0x3F5: "HUNK_OVERLAY",
    0x3F6: "HUNK_BREAK",
    0x3F7: "HUNK_DREL32",
    0x3F8: "HUNK_DREL16",
    0x3F9: "HUNK_DREL8",
    0x3FC: "HUNK_RELRELOC32",
    0x3FD: "HUNK_ABSRELOC16",
}


@dataclass
class ParsedExecutable:
    format: str
    architecture: str | None
    observations: Sequence[tuple[str, object]]
    assessments: list[Assessment]
    errors: list[str] = field(default_factory=list)


class ExecutableAnalyzer(GenericAnalyzer):
    analyzer_id = "executable"
    analyzer_class = ScannerClass.EXECUTABLE_ANALYZER
    product = "AVBox Bounded Executable Structure"

    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes

    def probe(self) -> ProbeResult:
        return ProbeResult(
            True,
            "built-in bounded PE/ELF/MZ/HUNK parser",
            QualificationState.PROBED,
            "1",
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        del artifact, job_id
        started = datetime.now(UTC)
        size = source.stat().st_size
        parsed: ParsedExecutable | None = None
        errors: list[str] = []
        if size > self.max_bytes:
            errors.append(f"executable parser byte limit exceeded: {size} > {self.max_bytes}")
            native_status = "unsupported_limit"
        else:
            data = source.read_bytes()
            try:
                parsed = parse_executable(data)
                native_status = "complete" if parsed is not None else "not_applicable"
                if parsed is not None and parsed.errors:
                    errors.extend(parsed.errors)
                    native_status = "partial_unsupported"
            except ExecutableError as exc:
                errors.append(str(exc))
                native_status = "corrupt"
        observations = []
        assessments: list[Assessment] = []
        if parsed is not None:
            pairs = [
                ("executable.format", parsed.format),
                ("executable.architecture", parsed.architecture),
                *parsed.observations,
            ]
            observations = [
                Observation(
                    observation_type=kind,
                    value=value,
                    analyzer_id=self.analyzer_id,
                    source="avbox-bounded-parser",
                    observed_at=started,
                    confidence="exact",
                )
                for kind, value in pairs
                if value is not None
            ]
            assessments = parsed.assessments
        completed = datetime.now(UTC)
        return AnalyzerResult(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="avbox.analyzers.executable.ExecutableAnalyzer",
            product_version="1",
            qualification_state=QualificationState.QUALIFIED,
            started_at=started,
            completed_at=completed,
            duration_seconds=(completed - started).total_seconds(),
            execution_profile="avbox-built-in-read-only-bounded",
            native_status=native_status,
            observations=observations,
            assessments=assessments,
            errors=errors,
        )


def _need(data: bytes, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ExecutableError(f"truncated {what}")


def _cstring(data: bytes, offset: int, limit: int = MAX_NAME) -> str:
    _need(data, offset, 1, "string")
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        raise ExecutableError("unterminated executable string")
    return data[offset:end].decode("utf-8", errors="replace")


def parse_executable(data: bytes) -> ParsedExecutable | None:
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return _parse_elf(data)
    if len(data) >= 4 and int.from_bytes(data[:4], "big") == 0x3F3:
        return _parse_hunk(data)
    magic = int.from_bytes(data[:4], "big") if len(data) >= 4 else 0
    if magic in {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA}:
        return _parse_macho(data)
    if len(data) >= 2 and data[:2] == b"MZ":
        return _parse_mz(data)
    return None


def _parse_mz(data: bytes) -> ParsedExecutable:
    _need(data, 0, 64, "DOS MZ header")
    last_bytes, pages, relocations, header_paragraphs = struct.unpack_from("<HHHH", data, 2)
    initial_ss, initial_sp, initial_ip, initial_cs = struct.unpack_from("<HHHH", data, 14)
    reloc_offset = struct.unpack_from("<H", data, 24)[0]
    new_offset = struct.unpack_from("<I", data, 60)[0]
    if relocations > MAX_HEADERS or reloc_offset + relocations * 4 > len(data):
        raise ExecutableError("MZ relocation table lies outside file or exceeds limit")
    kind = "DOS_MZ"
    extension: dict[str, object] = {}
    architecture = "X86_16"
    if new_offset:
        _need(data, new_offset, 2, "new executable header")
        signature = data[new_offset : new_offset + 4]
        if signature == b"PE\0\0":
            return _parse_pe(data, new_offset)
        if signature[:2] == b"NE":
            kind = "NE"
            _need(data, new_offset, 64, "NE header")
            extension = {
                "header_offset": new_offset,
                "linker_version": [data[new_offset + 2], data[new_offset + 3]],
                "entry_ip": struct.unpack_from("<H", data, new_offset + 20)[0],
                "entry_cs": struct.unpack_from("<H", data, new_offset + 22)[0],
                "segment_count": struct.unpack_from("<H", data, new_offset + 28)[0],
                "module_reference_count": struct.unpack_from("<H", data, new_offset + 30)[0],
                "target_os": data[new_offset + 54],
                "flags": struct.unpack_from("<H", data, new_offset + 12)[0],
            }
        elif signature[:2] in {b"LE", b"LX"}:
            kind = signature[:2].decode()
            _need(data, new_offset, 176, f"{kind} header")
            architecture = {1: "I286", 2: "I386", 3: "I486", 4: "I586"}.get(
                struct.unpack_from("<H", data, new_offset + 8)[0], "UNKNOWN"
            )
            extension = {
                "header_offset": new_offset,
                "byte_order": data[new_offset + 2],
                "word_order": data[new_offset + 3],
                "target_os": struct.unpack_from("<H", data, new_offset + 10)[0],
                "module_flags": struct.unpack_from("<I", data, new_offset + 16)[0],
                "object_count": struct.unpack_from("<I", data, new_offset + 68)[0],
                "entry_object": struct.unpack_from("<I", data, new_offset + 24)[0],
                "entry_offset": struct.unpack_from("<I", data, new_offset + 28)[0],
            }
    observations: list[tuple[str, object]] = [
        (
            "mz.header",
            {
                "dos_header_present": True,
                "pages": pages,
                "last_page_bytes": last_bytes,
                "header_paragraphs": header_paragraphs,
                "relocation_count": relocations,
                "relocation_table_offset": reloc_offset,
                "initial_cs": initial_cs,
                "initial_ip": initial_ip,
                "initial_ss": initial_ss,
                "initial_sp": initial_sp,
                "new_header_offset": new_offset,
            },
        ),
    ]
    if extension:
        observations.append((f"{kind.lower()}.header", extension))
    return ParsedExecutable(kind, architecture, observations, [])


def _parse_pe(data: bytes, offset: int) -> ParsedExecutable:
    _need(data, offset, 24, "PE COFF header")
    machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, offset + 4
    )
    if section_count > MAX_SECTIONS:
        raise ExecutableError("PE section count exceeds limit")
    optional = offset + 24
    _need(data, optional, optional_size, "PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in {0x10B, 0x20B}:
        raise ExecutableError(f"unsupported PE optional-header magic 0x{magic:04x}")
    is64 = magic == 0x20B
    minimum = 112 if is64 else 96
    if optional_size < minimum:
        raise ExecutableError("truncated PE optional header")
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    image_base = struct.unpack_from(
        "<Q" if is64 else "<I", data, optional + 24 if is64 else optional + 28
    )[0]
    subsystem, dll_characteristics = struct.unpack_from(
        "<HH",
        data,
        optional + 68,
    )
    directory_count = min(struct.unpack_from("<I", data, optional + (108 if is64 else 92))[0], 16)
    directory_start = optional + (112 if is64 else 96)
    directories: list[dict[str, object]] = []
    directory_names = [
        "export",
        "import",
        "resource",
        "exception",
        "security",
        "relocation",
        "debug",
        "architecture",
        "global_ptr",
        "tls",
        "load_config",
        "bound_import",
        "iat",
        "delay_import",
        "clr",
        "reserved",
    ]
    for index in range(directory_count):
        _need(data, directory_start + index * 8, 8, "PE data directory")
        rva, size = struct.unpack_from("<II", data, directory_start + index * 8)
        directories.append(
            {"index": index, "name": directory_names[index], "rva": rva, "size": size}
        )
    section_offset = optional + optional_size
    sections: list[dict[str, object]] = []
    for index in range(section_count):
        row = section_offset + index * 40
        _need(data, row, 40, "PE section header")
        name = data[row : row + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, row + 8)
        flags = struct.unpack_from("<I", data, row + 36)[0]
        if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
            raise ExecutableError(f"PE section {index} raw range lies outside file")
        sections.append(
            {
                "index": index,
                "name": name,
                "rva": rva,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": flags,
            }
        )

    def rva_offset(rva: object) -> int:
        numeric_rva = cast(int, rva)
        for section in sections:
            start = cast(int, section["rva"])
            span = max(cast(int, section["virtual_size"]), cast(int, section["raw_size"]))
            if start <= numeric_rva < start + span:
                value = cast(int, section["raw_offset"]) + numeric_rva - start
                _need(data, value, 1, "PE RVA")
                return value
        raise ExecutableError(f"PE RVA 0x{numeric_rva:x} is not mapped by a section")

    imports: list[dict[str, object]] = []
    if len(directories) > 1 and directories[1]["rva"]:
        cursor = rva_offset(directories[1]["rva"])
        for _ in range(MAX_IMPORTS):
            _need(data, cursor, 20, "PE import descriptor")
            original, _, _, name_rva, thunk = struct.unpack_from("<IIIII", data, cursor)
            if not any((original, name_rva, thunk)):
                break
            library = _cstring(data, rva_offset(name_rva))
            thunk_cursor = rva_offset(original or thunk)
            symbols: list[str | int] = []
            width, ordinal_flag = (8, 1 << 63) if is64 else (4, 1 << 31)
            for _ in range(MAX_IMPORTS):
                _need(data, thunk_cursor, width, "PE import thunk")
                value = int.from_bytes(data[thunk_cursor : thunk_cursor + width], "little")
                thunk_cursor += width
                if value == 0:
                    break
                if value & ordinal_flag:
                    symbols.append(value & 0xFFFF)
                else:
                    name_at = rva_offset(value)
                    _need(data, name_at, 2, "PE import hint")
                    symbols.append(_cstring(data, name_at + 2))
            else:
                raise ExecutableError("PE import symbol count exceeds limit")
            imports.append({"library": library, "symbols": symbols})
            cursor += 20
        else:
            raise ExecutableError("PE import descriptor count exceeds limit")
    exports: list[dict[str, object]] = []
    if directories and directories[0]["rva"]:
        exp = rva_offset(directories[0]["rva"])
        _need(data, exp, 40, "PE export directory")
        ordinal_base, function_count, name_count, _, names_rva, ordinals_rva = struct.unpack_from(
            "<IIIIII", data, exp + 16
        )
        if function_count > MAX_SYMBOLS or name_count > MAX_SYMBOLS:
            raise ExecutableError("PE export count exceeds limit")
        names_at, ordinals_at = rva_offset(names_rva), rva_offset(ordinals_rva)
        for index in range(name_count):
            _need(data, names_at + index * 4, 4, "PE export name pointer")
            _need(data, ordinals_at + index * 2, 2, "PE export ordinal")
            name_rva = struct.unpack_from("<I", data, names_at + index * 4)[0]
            ordinal = ordinal_base + struct.unpack_from("<H", data, ordinals_at + index * 2)[0]
            exports.append({"name": _cstring(data, rva_offset(name_rva)), "ordinal": ordinal})
    max_raw = max(
        (cast(int, item["raw_offset"]) + cast(int, item["raw_size"]) for item in sections),
        default=section_offset + section_count * 40,
    )
    security_end = 0
    if len(directories) > 4 and directories[4]["rva"]:
        security_end = cast(int, directories[4]["rva"]) + cast(int, directories[4]["size"])
    overlay_start = max(max_raw, security_end)
    overlay_size = max(0, len(data) - overlay_start)
    return ParsedExecutable(
        "PE32+" if is64 else "PE32",
        PE_MACHINES.get(machine, f"COFF_MACHINE_0x{machine:04X}"),
        [
            (
                "pe.coff",
                {
                    "dos_header_present": True,
                    "pe_signature": "PE\\0\\0",
                    "machine": machine,
                    "timestamp_raw": timestamp,
                    "characteristics": characteristics,
                    "section_count": section_count,
                },
            ),
            (
                "pe.optional",
                {
                    "entry_point_rva": entry,
                    "image_base": image_base,
                    "subsystem": subsystem,
                    "dll_characteristics": dll_characteristics,
                },
            ),
            ("pe.sections", sections),
            ("pe.data_directories", directories),
            ("pe.imports", imports),
            ("pe.exports", exports),
            (
                "pe.overlay",
                {"present": overlay_size > 0, "offset": overlay_start, "size": overlay_size},
            ),
        ],
        [],
    )


def _parse_elf(data: bytes) -> ParsedExecutable:
    _need(data, 0, 16, "ELF identification")
    elf_class, encoding = data[4], data[5]
    if elf_class not in {1, 2} or encoding not in {1, 2}:
        raise ExecutableError("invalid ELF class or byte order")
    endian = "<" if encoding == 1 else ">"
    is64 = elf_class == 2
    header_size = 64 if is64 else 52
    _need(data, 0, header_size, "ELF header")
    if is64:
        (
            object_type,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ) = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    else:
        (
            object_type,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ) = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
    if phnum > MAX_HEADERS or shnum > MAX_SECTIONS:
        raise ExecutableError("ELF header count exceeds limit")
    expected_ph, expected_sh = (56, 64) if is64 else (32, 40)
    if phnum and phentsize < expected_ph or shnum and shentsize < expected_sh:
        raise ExecutableError("invalid ELF entry size")
    _need(data, phoff, phentsize * phnum, "ELF program-header table")
    _need(data, shoff, shentsize * shnum, "ELF section-header table")
    programs: list[dict[str, int]] = []
    interpreter = None
    for index in range(phnum):
        row = phoff + index * phentsize
        if is64:
            ptype, pflags, poffset, vaddr, _, filesz, memsz, align = struct.unpack_from(
                endian + "IIQQQQQQ", data, row
            )
        else:
            ptype, poffset, vaddr, _, filesz, memsz, pflags, align = struct.unpack_from(
                endian + "IIIIIIII", data, row
            )
        if filesz:
            _need(data, poffset, filesz, "ELF segment")
        programs.append(
            {
                "index": index,
                "type": ptype,
                "flags": pflags,
                "offset": poffset,
                "virtual_address": vaddr,
                "file_size": filesz,
                "memory_size": memsz,
                "alignment": align,
            }
        )
        if ptype == 3 and filesz:
            interpreter = (
                data[poffset : poffset + filesz].rstrip(b"\0").decode("utf-8", errors="replace")
            )
    raw_sections: list[tuple[int, int, int, int, int, int, int]] = []
    for index in range(shnum):
        row = shoff + index * shentsize
        if is64:
            name, stype, sflags, _, soffset, ssize, link, _, _, entsize = struct.unpack_from(
                endian + "IIQQQQIIQQ", data, row
            )
        else:
            name, stype, sflags, _, soffset, ssize, link, _, _, entsize = struct.unpack_from(
                endian + "IIIIIIIIII", data, row
            )
        if stype != 8 and ssize:
            _need(data, soffset, ssize, "ELF section")
        raw_sections.append((name, stype, sflags, soffset, ssize, link, entsize))
    strings = b""
    if shnum and shstrndx < shnum:
        _, stype, _, soffset, ssize, _, _ = raw_sections[shstrndx]
        if stype == 3:
            strings = data[soffset : soffset + ssize]

    def section_name(value: int) -> str:
        if value >= len(strings):
            return f"<name:{value}>"
        end = strings.find(b"\0", value)
        return strings[value : end if end >= 0 else len(strings)].decode("utf-8", errors="replace")[
            :MAX_NAME
        ]

    sections = [
        {
            "index": index,
            "name": section_name(item[0]),
            "type": item[1],
            "flags": item[2],
            "offset": item[3],
            "size": item[4],
        }
        for index, item in enumerate(raw_sections)
    ]
    needed: list[str] = []
    soname = rpath = runpath = build_id = None
    symbol_count = 0
    for index, item in enumerate(raw_sections):
        _, stype, _, soffset, ssize, link, entsize = item
        if stype in {2, 11} and entsize:
            symbol_count += ssize // entsize
        if stype == 7 and sections[index]["name"] == ".note.gnu.build-id" and ssize >= 16:
            note = data[soffset : soffset + ssize]
            namesz, descsz, ntype = struct.unpack_from(endian + "III", note, 0)
            desc_at = 12 + ((namesz + 3) & ~3)
            if ntype == 3 and desc_at + descsz <= len(note):
                build_id = note[desc_at : desc_at + descsz].hex()
        if stype != 6 or not entsize or link >= len(raw_sections):
            continue
        _, strtype, _, stroff, strsize, _, _ = raw_sections[link]
        if strtype != 3:
            continue
        dynstr = data[stroff : stroff + strsize]
        count = ssize // entsize
        if count > MAX_SYMBOLS:
            raise ExecutableError("ELF dynamic entry count exceeds limit")
        for entry_index in range(count):
            row = soffset + entry_index * entsize
            tag, value = struct.unpack_from(endian + ("qQ" if is64 else "iI"), data, row)
            if tag not in {1, 14, 15, 29}:
                continue
            if value >= len(dynstr):
                raise ExecutableError("ELF dynamic string offset lies outside table")
            end = dynstr.find(b"\0", value)
            text = dynstr[value : end if end >= 0 else len(dynstr)].decode(
                "utf-8", errors="replace"
            )[:MAX_NAME]
            if tag == 1:
                needed.append(text)
            elif tag == 14:
                soname = text
            elif tag == 15:
                rpath = text
            else:
                runpath = text
    if symbol_count > MAX_SYMBOLS:
        raise ExecutableError("ELF symbol count exceeds limit")
    assessments: list[Assessment] = []
    names = {str(item["name"]) for item in sections}
    if object_type in {2, 3} and ".symtab" not in names:
        assessments.append(
            Assessment(
                assessment_type="LIKELY_STRIPPED",
                analyzer_id="executable",
                statement="ELF executable/shared object has no static symbol table",
                confidence=Confidence.MEDIUM,
                evidence_refs=["elf.sections"],
            )
        )
    return ParsedExecutable(
        "ELF64" if is64 else "ELF32",
        ELF_MACHINES.get(machine, f"ELF_MACHINE_{machine}"),
        [
            (
                "elf.header",
                {
                    "class": elf_class,
                    "endianness": "little" if encoding == 1 else "big",
                    "os_abi": data[7],
                    "object_type": object_type,
                    "machine": machine,
                    "version": version,
                    "entry_point": entry,
                    "flags": flags,
                    "header_size": ehsize,
                },
            ),
            ("elf.program_headers", programs),
            ("elf.sections", sections),
            ("elf.interpreter", interpreter),
            (
                "elf.dynamic",
                {"needed": needed, "soname": soname, "rpath": rpath, "runpath": runpath},
            ),
            ("elf.symbol_count", symbol_count),
            ("elf.build_id", build_id),
        ],
        assessments,
    )


def _parse_hunk(data: bytes) -> ParsedExecutable:
    cursor = 4
    resident: list[str] = []
    while True:
        _need(data, cursor, 4, "HUNK resident-name length")
        longs = int.from_bytes(data[cursor : cursor + 4], "big")
        cursor += 4
        if longs == 0:
            break
        if longs > MAX_NAME // 4:
            raise ExecutableError("HUNK resident name exceeds limit")
        _need(data, cursor, longs * 4, "HUNK resident name")
        resident.append(
            data[cursor : cursor + longs * 4].rstrip(b"\0").decode("latin-1", errors="replace")
        )
        cursor += longs * 4
    _need(data, cursor, 12, "HUNK header table")
    table_size, first, last = struct.unpack_from(">III", data, cursor)
    cursor += 12
    if (
        table_size == 0
        or table_size > MAX_SECTIONS
        or last < first
        or last - first + 1 != table_size
    ):
        raise ExecutableError("invalid HUNK table range/count")
    _need(data, cursor, table_size * 4, "HUNK size table")
    declared = []
    for _ in range(table_size):
        raw = int.from_bytes(data[cursor : cursor + 4], "big")
        cursor += 4
        declared.append({"size_longs": raw & 0x3FFFFFFF, "memory_flags": raw >> 30})
    records: list[dict[str, object]] = []
    current_hunk = first
    ended = 0
    while cursor < len(data):
        _need(data, cursor, 4, "HUNK record")
        raw_type = int.from_bytes(data[cursor : cursor + 4], "big")
        cursor += 4
        hunk_type = raw_type & 0x3FFFFFFF
        name = HUNK_TYPES.get(hunk_type, f"HUNK_UNKNOWN_{hunk_type}")
        record: dict[str, object] = {
            "type_id": hunk_type,
            "type": name,
            "memory_flags": raw_type >> 30,
            "hunk_index": current_hunk,
        }
        if hunk_type in {0x3E9, 0x3EA, 0x3EB, 0x3F1}:
            _need(data, cursor, 4, f"{name} size")
            longs = int.from_bytes(data[cursor : cursor + 4], "big")
            cursor += 4
            record["size_longs"] = longs
            record["size_bytes"] = longs * 4
            if hunk_type != 0x3EB:
                _need(data, cursor, longs * 4, name)
                cursor += longs * 4
        elif hunk_type in {0x3EC, 0x3ED, 0x3EE, 0x3F7, 0x3F8, 0x3F9, 0x3FC, 0x3FD}:
            groups: list[dict[str, object]] = []
            while True:
                _need(data, cursor, 4, f"{name} count")
                count = int.from_bytes(data[cursor : cursor + 4], "big")
                cursor += 4
                if count == 0:
                    break
                if count > MAX_SYMBOLS:
                    raise ExecutableError("HUNK relocation count exceeds limit")
                _need(data, cursor, 4 + count * 4, f"{name} offsets")
                target = int.from_bytes(data[cursor : cursor + 4], "big")
                cursor += 4
                offsets = list(struct.unpack_from(f">{count}I", data, cursor))
                cursor += count * 4
                groups.append({"target_hunk": target, "offsets": offsets})
            record["relocations"] = groups
        elif hunk_type == 0x3F0:
            symbols: list[dict[str, object]] = []
            while True:
                _need(data, cursor, 4, "HUNK symbol name length")
                longs = int.from_bytes(data[cursor : cursor + 4], "big")
                cursor += 4
                if longs == 0:
                    break
                if len(symbols) >= MAX_SYMBOLS or longs > MAX_NAME // 4:
                    raise ExecutableError("HUNK symbol limit exceeded")
                _need(data, cursor, longs * 4 + 4, "HUNK symbol")
                symbol = (
                    data[cursor : cursor + longs * 4]
                    .rstrip(b"\0")
                    .decode("latin-1", errors="replace")
                )
                cursor += longs * 4
                value = int.from_bytes(data[cursor : cursor + 4], "big")
                cursor += 4
                symbols.append({"name": symbol, "value": value})
            record["symbols"] = symbols
        elif hunk_type == 0x3F2:
            ended += 1
            current_hunk += 1
        else:
            record["unsupported"] = True
            records.append(record)
            return ParsedExecutable(
                "AMIGA_HUNK",
                "M68K",
                [
                    (
                        "hunk.header",
                        {
                            "resident_names": resident,
                            "hunk_count": table_size,
                            "first_hunk": first,
                            "last_hunk": last,
                            "declared_hunks": declared,
                        },
                    ),
                    ("hunk.records", records),
                ],
                [
                    Assessment(
                        assessment_type="EXECUTABLE_STRUCTURE_ANOMALY",
                        analyzer_id="executable",
                        statement=f"unsupported HUNK record type {hunk_type}",
                        confidence=Confidence.HIGH,
                        evidence_refs=["hunk.records"],
                    )
                ],
                [f"unsupported HUNK record type {hunk_type}"],
            )
        records.append(record)
        if ended == table_size:
            break
        if len(records) > MAX_HEADERS:
            raise ExecutableError("HUNK record count exceeds limit")
    if ended != table_size:
        raise ExecutableError("HUNK file lacks required HUNK_END records")
    return ParsedExecutable(
        "AMIGA_HUNK",
        "M68K",
        [
            (
                "hunk.header",
                {
                    "resident_names": resident,
                    "hunk_count": table_size,
                    "first_hunk": first,
                    "last_hunk": last,
                    "declared_hunks": declared,
                },
            ),
            ("hunk.records", records),
        ],
        [],
    )


def _parse_macho(data: bytes) -> ParsedExecutable:
    raw = int.from_bytes(data[:4], "big")
    if raw in {0xCAFEBABE, 0xBEBAFECA}:
        endian = ">" if raw == 0xCAFEBABE else "<"
        _need(data, 0, 8, "Mach-O FAT header")
        count = struct.unpack_from(endian + "I", data, 4)[0]
        if count > 64:
            raise ExecutableError("Mach-O FAT architecture count exceeds limit")
        _need(data, 8, count * 20, "Mach-O FAT architecture table")
        architectures = []
        for index in range(count):
            cpu, subtype, offset, size, align = struct.unpack_from(
                endian + "IIIII", data, 8 + index * 20
            )
            _need(data, offset, size, "Mach-O FAT slice")
            architectures.append(
                {
                    "index": index,
                    "cpu_type": cpu,
                    "cpu_subtype": subtype,
                    "offset": offset,
                    "size": size,
                    "alignment_power": align,
                }
            )
        return ParsedExecutable("MACHO_FAT", None, [("macho.fat_architectures", architectures)], [])
    little = raw in {0xCEFAEDFE, 0xCFFAEDFE}
    is64 = raw in {0xFEEDFACF, 0xCFFAEDFE}
    endian = "<" if little else ">"
    header_size = 32 if is64 else 28
    _need(data, 0, header_size, "Mach-O header")
    cpu, subtype, file_type, commands, command_bytes, flags = struct.unpack_from(
        endian + "IIIIII", data, 4
    )
    if commands > MAX_HEADERS or command_bytes > len(data) - header_size:
        raise ExecutableError("Mach-O load-command bounds exceeded")
    cursor = header_size
    loads: list[dict[str, int]] = []
    for index in range(commands):
        _need(data, cursor, 8, "Mach-O load command")
        command, size = struct.unpack_from(endian + "II", data, cursor)
        if size < 8:
            raise ExecutableError("invalid Mach-O load-command size")
        _need(data, cursor, size, "Mach-O load command")
        loads.append({"index": index, "command": command, "size": size, "offset": cursor})
        cursor += size
    architecture = {7: "I386", 0x01000007: "X86_64", 12: "ARM", 0x0100000C: "ARM64"}.get(
        cpu, f"MACH_CPU_{cpu}"
    )
    return ParsedExecutable(
        "MACHO64" if is64 else "MACHO32",
        architecture,
        [
            (
                "macho.header",
                {
                    "magic": f"0x{raw:08X}",
                    "endianness": "little" if little else "big",
                    "cpu_type": cpu,
                    "cpu_subtype": subtype,
                    "file_type": file_type,
                    "load_command_count": commands,
                    "load_command_bytes": command_bytes,
                    "flags": flags,
                },
            ),
            ("macho.load_commands", loads),
        ],
        [],
    )
