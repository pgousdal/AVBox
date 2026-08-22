from __future__ import annotations

import re
import struct
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

from avbox.analyzers.generic import GenericAnalyzer
from avbox.config.settings import RuntimeSettings
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

ANALYZER_ID = "document"
MAX_STRING = 4096
PDF_OBJECT = re.compile(rb"(?m)(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj\b", re.S)
URL = re.compile(rb"(?i)\b(?:https?|ftp)://[^\s<>\[\](){}\x00-\x1f]+")
AUTO_NAMES = ("AutoOpen", "AutoExec", "Document_Open", "Workbook_Open", "Presentation_Open")


class DocumentError(ValueError):
    pass


@dataclass
class DocumentChild:
    name: str
    data: bytes
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class ParsedDocument:
    format: str
    observations: list[tuple[str, object]]
    assessments: list[Assessment] = field(default_factory=list)
    children: list[DocumentChild] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    partial: str | None = None


def _assessment(kind: str, statement: str, confidence: Confidence, refs: list[str]) -> Assessment:
    return Assessment(
        assessment_type=kind,
        analyzer_id=ANALYZER_ID,
        statement=statement,
        confidence=confidence,
        evidence_refs=refs,
    )


class DocumentAnalyzer(GenericAnalyzer):
    analyzer_id = ANALYZER_ID
    analyzer_class = ScannerClass.DOCUMENT_ANALYZER
    product = "AVBox Bounded Document Structure"

    def __init__(self, limits: RuntimeSettings):
        self.limits = limits
        self.max_bytes = limits.max_document_parser_bytes

    def probe(self) -> ProbeResult:
        return ProbeResult(
            True,
            "built-in bounded non-rendering document parser",
            QualificationState.QUALIFIED,
            "1",
        )

    def analyze(self, artifact: InputArtifact, source: Path, job_id: str) -> AnalyzerResult:
        del job_id
        started = datetime.now(UTC)
        errors: list[str] = []
        parsed: ParsedDocument | None = None
        size = source.stat().st_size
        if size > self.max_bytes:
            status = "unsupported_limit"
            errors.append(f"document parser byte limit exceeded: {size} > {self.max_bytes}")
        else:
            try:
                parsed = parse_document(source, self.limits)
                status = "not_applicable" if parsed is None else parsed.partial or "complete"
                if parsed:
                    errors.extend(parsed.errors)
            except (DocumentError, OSError, zipfile.BadZipFile, ET.ParseError) as exc:
                status = "corrupt"
                errors.append(str(exc))
        observations: list[Observation] = []
        assessments: list[Assessment] = []
        if parsed:
            pairs = [("document.format", parsed.format), *parsed.observations]
            observations = [
                Observation(
                    observation_type=kind,
                    value=value,
                    analyzer_id=self.analyzer_id,
                    source="avbox-bounded-document-parser",
                    observed_at=started,
                    confidence="exact",
                )
                for kind, value in pairs
            ]
            assessments = parsed.assessments
            extension = PurePosixPath(artifact.filename or "").suffix.lower().lstrip(".")
            expected = _expected_extensions(parsed.format)
            if extension and expected and extension not in expected:
                assessments.append(
                    _assessment(
                        "EXTENSION_DOCUMENT_TYPE_MISMATCH",
                        f"extension .{extension} does not match internally identified "
                        f"{parsed.format}",
                        Confidence.HIGH,
                        ["document.format"],
                    )
                )
        completed = datetime.now(UTC)
        return AnalyzerResult(
            analyzer_id=self.analyzer_id,
            analyzer_class=self.analyzer_class,
            product=self.product,
            implementation="avbox.analyzers.document.DocumentAnalyzer",
            product_version="1",
            qualification_state=QualificationState.QUALIFIED,
            started_at=started,
            completed_at=completed,
            duration_seconds=(completed - started).total_seconds(),
            execution_profile="avbox-built-in-read-only-bounded-no-network-no-render-no-execution",
            native_status=status,
            observations=observations,
            assessments=assessments,
            errors=errors,
        )


def _expected_extensions(fmt: str) -> set[str]:
    values = {
        "PDF": {"pdf"},
        "OLE_DOC": {"doc", "dot"},
        "OLE_XLS": {"xls", "xlt"},
        "OLE_PPT": {"ppt", "pot", "pps"},
        "OOXML_DOCX": {"docx"},
        "OOXML_XLSX": {"xlsx"},
        "OOXML_PPTX": {"pptx"},
        "OOXML_DOCM": {"docm", "dotm"},
        "OOXML_XLSM": {"xlsm", "xltm"},
        "OOXML_PPTM": {"pptm", "potm", "ppsm"},
        "RTF": {"rtf"},
        "ODF_ODT": {"odt"},
        "ODF_ODS": {"ods"},
        "ODF_ODP": {"odp"},
    }
    return values.get(fmt, set())


def parse_document(source: Path, limits: RuntimeSettings) -> ParsedDocument | None:
    with source.open("rb") as stream:
        head = stream.read(16)
    if head.startswith(b"%PDF-"):
        return _parse_pdf(source.read_bytes(), limits)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _parse_cfb(source.read_bytes(), limits)
    if head.lstrip().startswith(b"{\\rtf"):
        return _parse_rtf(source.read_bytes(), limits)
    if zipfile.is_zipfile(source):
        return _parse_package(source, limits)
    if head.startswith(b"PK"):
        raise DocumentError("truncated or malformed ZIP-based document")
    return None


def _parse_pdf(data: bytes, limits: RuntimeSettings) -> ParsedDocument:
    match = re.match(rb"%PDF-(\d\.\d)", data)
    if not match:
        raise DocumentError("invalid PDF header")
    objects = list(PDF_OBJECT.finditer(data))
    if len(objects) > limits.max_document_components:
        raise DocumentError("PDF object count limit exceeded")
    bodies = {int(item.group(1)): item.group(3) for item in objects}
    obs: list[tuple[str, object]] = [
        ("pdf.version", match.group(1).decode("ascii")),
        ("pdf.eof_marker_present", b"%%EOF" in data[-4096:]),
        ("pdf.indirect_object_count", len(objects)),
        ("pdf.stream_count", len(re.findall(rb"(?m)\bstream\r?\n", data))),
        ("pdf.xref_table_present", bool(re.search(rb"(?m)^xref\s*$", data))),
        ("pdf.xref_stream_present", b"/Type/XRef" in data or b"/Type /XRef" in data),
        ("pdf.trailer_present", b"trailer" in data),
        ("pdf.encryption_present", b"/Encrypt" in data),
        ("pdf.metadata_present", b"/Metadata" in data or b"/Info" in data),
        ("pdf.xmp_present", b"application/rdf+xml" in data or b"<x:xmpmeta" in data),
        ("pdf.names_tree_present", b"/Names" in data),
        ("pdf.javascript_present", b"/JavaScript" in data or b"/JS" in data),
        ("pdf.javascript_action_present", bool(re.search(rb"/S\s*/JavaScript", data))),
        ("pdf.open_action_present", b"/OpenAction" in data),
        ("pdf.additional_actions_present", bool(re.search(rb"/AA\b", data))),
        ("pdf.launch_action_present", bool(re.search(rb"/S\s*/Launch", data))),
        ("pdf.uri_action_present", bool(re.search(rb"/S\s*/URI", data))),
        ("pdf.acroform_present", b"/AcroForm" in data),
        ("pdf.xfa_present", b"/XFA" in data),
        ("pdf.signature_structure_present", b"/Sig" in data or b"/Type/Sig" in data),
        ("pdf.object_stream_count", len(re.findall(rb"/Type\s*/ObjStm", data))),
    ]
    pages = len(re.findall(rb"/Type\s*/Page(?!s)\b", data))
    obs.append(("pdf.page_count", pages))
    eof_count = len(re.findall(rb"%%EOF", data))
    startxref_count = len(re.findall(rb"startxref", data))
    obs.append(("pdf.incremental_update_sections", max(eof_count, startxref_count)))
    urls = sorted({item.decode("utf-8", "replace")[:MAX_STRING] for item in URL.findall(data)})
    for value in urls[: limits.metadata_max_fields]:
        obs.append(("document.external_url", value))
    children: list[DocumentChild] = []
    for number, body in bodies.items():
        if not re.search(rb"/Type\s*/EmbeddedFile\b", body):
            continue
        stream = re.search(rb"stream\r?\n(.*?)\r?\nendstream", body, re.S)
        if not stream:
            continue
        payload = stream.group(1)
        if b"/FlateDecode" in body:
            import zlib

            try:
                decompressor = zlib.decompressobj()
                payload = decompressor.decompress(payload, limits.max_single_child_bytes + 1)
                if decompressor.unconsumed_tail:
                    continue
            except (zlib.error, TypeError):
                continue
        if len(payload) <= limits.max_single_child_bytes:
            children.append(
                DocumentChild(f"pdf-embedded-{number}.bin", payload, {"pdf_object": number})
            )
    obs.extend(
        [
            ("pdf.embedded_file_count", len(children)),
            ("pdf.embedded_file_structure_present", bool(children) or b"/EmbeddedFiles" in data),
        ]
    )
    assessments: list[Assessment] = []
    if any(
        value
        for kind, value in obs
        if kind in {"pdf.javascript_present", "pdf.launch_action_present"}
    ):
        assessments.append(
            _assessment(
                "ACTIVE_CONTENT_PRESENT",
                "PDF contains active-content structures",
                Confidence.HIGH,
                ["pdf.javascript_present", "pdf.launch_action_present"],
            )
        )
    if children:
        assessments.append(
            _assessment(
                "EMBEDDED_OBJECT_PRESENT",
                "PDF contains bounded extractable embedded file payloads",
                Confidence.HIGH,
                ["pdf.embedded_file_count"],
            )
        )
    if urls:
        assessments.append(
            _assessment(
                "EXTERNAL_REFERENCE_PRESENT",
                "PDF contains external URL values; none were fetched",
                Confidence.HIGH,
                ["document.external_url"],
            )
        )
    if b"/Encrypt" in data:
        assessments.append(
            _assessment(
                "ENCRYPTED_DOCUMENT",
                "PDF contains encryption metadata; no password was attempted",
                Confidence.HIGH,
                ["pdf.encryption_present"],
            )
        )
    if eof_count > 1 or startxref_count > 1:
        assessments.append(
            _assessment(
                "INCREMENTAL_PDF_UPDATES",
                "PDF contains multiple update terminators",
                Confidence.HIGH,
                ["pdf.incremental_update_sections"],
            )
        )
    eof_missing = b"%%EOF" not in data[-4096:]
    errors = ["PDF EOF marker absent"] if eof_missing else []
    partial = "partial_error" if errors else None
    if b"/Encrypt" in data:
        errors.append("PDF encryption prevents complete content inspection")
        partial = "partial_unsupported"
    if eof_missing:
        assessments.append(
            _assessment(
                "DOCUMENT_STRUCTURE_ANOMALY",
                "PDF EOF marker absent",
                Confidence.HIGH,
                ["pdf.eof_marker_present"],
            )
        )
    return ParsedDocument(
        "PDF", obs, assessments, children, errors, partial
    )


@dataclass
class _CfbEntry:
    entry_id: int
    name: str
    kind: int
    clsid: str
    start: int
    size: int
    left_sibling: int
    right_sibling: int
    child: int
    data: bytes = b""
    path: str = ""


def _decompress_vba(data: bytes, maximum: int) -> bytes | None:
    """Decompress an MS-OVBA CompressedContainer without executing source."""
    if not data or data[0] != 1:
        return None
    output = bytearray()
    cursor = 1
    try:
        while cursor < len(data):
            if cursor + 2 > len(data):
                return None
            header = struct.unpack_from("<H", data, cursor)[0]
            chunk_size = (header & 0x0FFF) + 3
            chunk_end = cursor + chunk_size
            if header & 0x7000 != 0x3000 or chunk_end > len(data):
                return None
            compressed = bool(header & 0x8000)
            cursor += 2
            chunk_start = len(output)
            if not compressed:
                output.extend(data[cursor:chunk_end])
                cursor = chunk_end
            else:
                while cursor < chunk_end:
                    flags = data[cursor]
                    cursor += 1
                    for bit in range(8):
                        if cursor >= chunk_end:
                            break
                        if flags & (1 << bit):
                            if cursor + 2 > chunk_end:
                                return None
                            token = struct.unpack_from("<H", data, cursor)[0]
                            cursor += 2
                            position = len(output) - chunk_start
                            bit_count = max(4, max(1, position).bit_length())
                            length_bits = 16 - bit_count
                            length = (token & ((1 << length_bits) - 1)) + 3
                            offset = (token >> length_bits) + 1
                            if offset > position:
                                return None
                            for _ in range(length):
                                output.append(output[-offset])
                                if len(output) > maximum:
                                    return None
                        else:
                            output.append(data[cursor])
                            cursor += 1
                            if len(output) > maximum:
                                return None
            if len(output) > maximum:
                return None
    except (IndexError, struct.error):
        return None
    return bytes(output)


def _parse_cfb(data: bytes, limits: RuntimeSettings) -> ParsedDocument:
    if len(data) < 512:
        raise DocumentError("truncated CFB header")
    major = struct.unpack_from("<H", data, 26)[0]
    sector_shift = struct.unpack_from("<H", data, 30)[0]
    mini_shift = struct.unpack_from("<H", data, 32)[0]
    sector_size = 1 << sector_shift
    if major not in {3, 4} or sector_size not in {512, 4096} or 1 << mini_shift != 64:
        raise DocumentError("invalid CFB version or sector geometry")
    total_sectors = (len(data) - 512) // sector_size
    fat_count = struct.unpack_from("<I", data, 44)[0]
    first_dir = struct.unpack_from("<I", data, 48)[0]
    mini_cutoff = struct.unpack_from("<I", data, 56)[0]
    first_minifat = struct.unpack_from("<I", data, 60)[0]
    minifat_count = struct.unpack_from("<I", data, 64)[0]
    difat = list(struct.unpack_from("<109I", data, 76))
    fat_sectors = [value for value in difat if value < 0xFFFFFFFA][:fat_count]
    if fat_count > 109 or len(fat_sectors) != fat_count:
        raise DocumentError("CFB DIFAT extension unsupported or corrupt")

    def sector(sid: int) -> bytes:
        if sid < 0 or sid >= total_sectors:
            raise DocumentError("CFB sector outside file")
        offset = 512 + sid * sector_size
        return data[offset : offset + sector_size]

    fat: list[int] = []
    for sid in fat_sectors:
        fat.extend(struct.unpack(f"<{sector_size // 4}I", sector(sid)))

    def chain(start: int, table: list[int], maximum: int) -> list[int]:
        result: list[int] = []
        seen: set[int] = set()
        current = start
        while current < 0xFFFFFFFA:
            if current in seen or current >= len(table) or len(result) >= maximum:
                raise DocumentError("CFB cyclic or excessive allocation chain")
            seen.add(current)
            result.append(current)
            current = table[current]
        return result

    max_components = limits.max_document_components
    directory = b"".join(sector(sid) for sid in chain(first_dir, fat, max_components))
    entries: list[_CfbEntry] = []
    for offset in range(0, len(directory), 128):
        raw = directory[offset : offset + 128]
        if len(raw) < 128:
            break
        name_len = struct.unpack_from("<H", raw, 64)[0]
        kind = raw[66]
        if not kind or name_len < 2 or name_len > 64:
            continue
        name = raw[: name_len - 2].decode("utf-16le", "replace")[:MAX_STRING]
        clsid_raw = raw[80:96]
        clsid = clsid_raw.hex() if any(clsid_raw) else ""
        left_sibling, right_sibling, child = struct.unpack_from("<III", raw, 68)
        start = struct.unpack_from("<I", raw, 116)[0]
        size = struct.unpack_from("<Q", raw, 120)[0]
        entries.append(
            _CfbEntry(
                offset // 128,
                name,
                kind,
                clsid,
                start,
                size,
                left_sibling,
                right_sibling,
                child,
            )
        )
        if len(entries) > max_components:
            raise DocumentError("CFB directory entry limit exceeded")
    root = next((entry for entry in entries if entry.kind == 5), None)
    by_id = {entry.entry_id: entry for entry in entries}

    def assign_tree(entry_id: int, parent: str, seen: set[int]) -> None:
        if entry_id >= 0xFFFFFFFA or entry_id in seen or entry_id not in by_id:
            return
        seen.add(entry_id)
        entry = by_id[entry_id]
        assign_tree(entry.left_sibling, parent, seen)
        entry.path = f"{parent}/{entry.name}" if parent else entry.name
        if entry.kind == 1:
            assign_tree(entry.child, entry.path, seen)
        assign_tree(entry.right_sibling, parent, seen)

    if root:
        root.path = root.name
        assign_tree(root.child, "", set())
    minifat: list[int] = []
    if minifat_count and first_minifat < 0xFFFFFFFA:
        raw = b"".join(sector(sid) for sid in chain(first_minifat, fat, minifat_count))
        minifat = list(struct.unpack(f"<{len(raw) // 4}I", raw))
    ministream = b""
    if root and root.size and root.start < 0xFFFFFFFA:
        ministream = b"".join(sector(sid) for sid in chain(root.start, fat, max_components))[
            : root.size
        ]
    for entry in entries:
        if entry.kind != 2 or not entry.size:
            continue
        if entry.size > limits.max_document_parser_bytes:
            continue
        if entry.size < mini_cutoff and minifat and ministream:
            chunks = chain(entry.start, minifat, max_components)
            entry.data = b"".join(ministream[sid * 64 : (sid + 1) * 64] for sid in chunks)[
                : entry.size
            ]
        elif entry.start < 0xFFFFFFFA:
            entry.data = b"".join(sector(sid) for sid in chain(entry.start, fat, max_components))[
                : entry.size
            ]
    names = [entry.name for entry in entries]
    name_set = set(names)
    family = "OLE_CFB"
    if "WordDocument" in name_set:
        family = "OLE_DOC"
    elif "Workbook" in name_set or "Book" in name_set:
        family = "OLE_XLS"
    elif "PowerPoint Document" in name_set:
        family = "OLE_PPT"
    macro_entries = [
        entry
        for entry in entries
        if entry.name.lower() in {"dir", "project", "_vba_project"}
        or "vba" in entry.path.lower()
    ]
    module_sources: list[tuple[_CfbEntry, bytes]] = []
    for entry in entries:
        if entry.kind != 2 or entry.name in {
            "dir",
            "PROJECT",
            "PROJECTwm",
            "_VBA_PROJECT",
        }:
            continue
        source = _decompress_vba(entry.data, limits.max_document_parser_bytes) or entry.data
        if entry.path.startswith("VBA/") and not entry.name.startswith("__SRP_"):
            module_sources.append((entry, source))
        elif any(token in source for token in (b"Attribute VB_", b"Sub ", b"Function ")):
            module_sources.append((entry, source))
    auto = sorted(
        {name for _, source in module_sources for name in AUTO_NAMES if name.encode() in source}
    )
    package = [
        entry
        for entry in entries
        if entry.kind == 2 and entry.name in {"Package", "CONTENTS", "Ole10Native"}
    ]
    children = [
        DocumentChild(f"ole-{entry.name}.bin", entry.data, {"cfb_stream": entry.name})
        for entry in package
        if entry.data and len(entry.data) <= limits.max_single_child_bytes
    ]
    obs: list[tuple[str, object]] = [
        ("cfb.major_version", major),
        ("cfb.sector_size", sector_size),
        ("cfb.mini_sector_size", 1 << mini_shift),
        ("cfb.directory_entry_count", len(entries)),
        ("cfb.stream_count", sum(entry.kind == 2 for entry in entries)),
        ("cfb.storage_count", sum(entry.kind in {1, 5} for entry in entries)),
        (
            "cfb.directory_hierarchy",
            [
                {
                    "id": e.entry_id,
                    "name": e.name,
                    "kind": {1: "storage", 2: "stream", 5: "root"}.get(e.kind, "unknown"),
                    "left_sibling": e.left_sibling if e.left_sibling < 0xFFFFFFFA else None,
                    "right_sibling": e.right_sibling if e.right_sibling < 0xFFFFFFFA else None,
                    "child": e.child if e.child < 0xFFFFFFFA else None,
                }
                for e in entries
            ],
        ),
        ("cfb.streams", [{"name": e.name, "size": e.size} for e in entries if e.kind == 2]),
        ("cfb.clsids", sorted({e.clsid for e in entries if e.clsid})),
        ("cfb.summary_information_present", "\x05SummaryInformation" in name_set),
        ("cfb.document_summary_information_present", "\x05DocumentSummaryInformation" in name_set),
        (
            "cfb.summary_information_stream_size",
            next((e.size for e in entries if e.name == "\x05SummaryInformation"), 0),
        ),
        (
            "cfb.document_summary_information_stream_size",
            next((e.size for e in entries if e.name == "\x05DocumentSummaryInformation"), 0),
        ),
        ("document.vba_project_present", bool(macro_entries or module_sources)),
        ("document.vba_module_count", len(module_sources)),
        (
            "document.vba_modules",
            [
                {
                    "name": entry.name,
                    "path": entry.path,
                    "type": "module",
                    "source_present": bool(source),
                }
                for entry, source in module_sources
            ],
        ),
        ("document.vba_auto_entry_points", auto),
        ("cfb.embedded_object_present", bool(package or any("ObjectPool" in n for n in names))),
        (
            "cfb.encryption_structure_present",
            any(n in {"EncryptionInfo", "EncryptedPackage"} or "Crypt" in n for n in names),
        ),
        (
            "cfb.signature_structure_present",
            any("DigitalSignature" in n or n == "_xmlsignatures" for n in names),
        ),
    ]
    assessments: list[Assessment] = []
    if macro_entries or module_sources:
        assessments.append(
            _assessment(
                "ACTIVE_CONTENT_PRESENT",
                "CFB contains VBA project/module structures",
                Confidence.HIGH,
                ["document.vba_project_present"],
            )
        )
    if children or any("ObjectPool" in n for n in names):
        assessments.append(
            _assessment(
                "EMBEDDED_OBJECT_PRESENT",
                "CFB contains embedded object/package structures",
                Confidence.HIGH,
                ["cfb.embedded_object_present"],
            )
        )
    return ParsedDocument(family, obs, assessments, children)


def _safe_xml(data: bytes, limits: RuntimeSettings) -> ET.Element:
    if len(data) > limits.max_document_parser_bytes:
        raise DocumentError("XML part size limit exceeded")
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise DocumentError("XML DTD/entity declarations forbidden")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise DocumentError(f"malformed XML part: {exc}") from exc
    count = 0
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > limits.max_document_xml_depth:
            raise DocumentError("XML nesting limit exceeded")
        if count > limits.max_document_components:
            raise DocumentError("XML element count limit exceeded")
        if len(node.attrib) > limits.metadata_max_fields:
            raise DocumentError("XML attribute count limit exceeded")
        stack.extend((child, depth + 1) for child in node)
    return root


def _parse_package(source: Path, limits: RuntimeSettings) -> ParsedDocument | None:
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        if len(infos) > limits.max_document_components:
            raise DocumentError("document package component limit exceeded")
        expanded = sum(info.file_size for info in infos)
        if expanded > limits.max_document_parser_bytes:
            raise DocumentError("document package expanded-size limit exceeded")
        names = {info.filename for info in infos}
        if "[Content_Types].xml" in names:
            return _parse_ooxml(archive, infos, limits)
        if "mimetype" in names and "META-INF/manifest.xml" in names:
            return _parse_odf(archive, infos, limits)
    return None


def _read_part(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limits: RuntimeSettings) -> bytes:
    if info.flag_bits & 1:
        raise DocumentError("encrypted ZIP package member")
    if info.file_size > limits.max_document_parser_bytes:
        raise DocumentError("document package member size limit exceeded")
    with archive.open(info) as stream:
        data = stream.read(limits.max_document_parser_bytes + 1)
    if len(data) > limits.max_document_parser_bytes:
        raise DocumentError("document package member expanded size limit exceeded")
    return data


def _parse_ooxml(
    archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], limits: RuntimeSettings
) -> ParsedDocument:
    by_name = {info.filename: info for info in infos}
    content = _read_part(archive, by_name["[Content_Types].xml"], limits)
    root = _safe_xml(content, limits)
    content_types = " ".join(str(value) for node in root for value in node.attrib.values())
    family = "OOXML"
    if "wordprocessingml" in content_types:
        family = "OOXML_DOCX"
    elif "spreadsheetml" in content_types:
        family = "OOXML_XLSX"
    elif "presentationml" in content_types:
        family = "OOXML_PPTX"
    macro = "macroEnabled" in content_types or any(
        info.filename.endswith("vbaProject.bin") for info in infos
    )
    if macro:
        family = {
            "OOXML_DOCX": "OOXML_DOCM",
            "OOXML_XLSX": "OOXML_XLSM",
            "OOXML_PPTX": "OOXML_PPTM",
        }.get(family, family)
    relationships: list[dict[str, str]] = []
    external: list[dict[str, str]] = []
    for info in infos:
        if not info.filename.endswith(".rels"):
            continue
        relroot = _safe_xml(_read_part(archive, info, limits), limits)
        for node in relroot:
            item = {
                key.rsplit("}", 1)[-1]: value[:MAX_STRING] for key, value in node.attrib.items()
            }
            item["part"] = info.filename
            relationships.append(item)
            if item.get("TargetMode", "").lower() == "external":
                external.append(item)
            if len(relationships) > limits.metadata_max_fields:
                raise DocumentError("OOXML relationship count limit exceeded")
    embedded_prefixes = ("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")
    child_infos = [
        info
        for info in infos
        if info.filename.startswith(embedded_prefixes) or info.filename.endswith("vbaProject.bin")
    ]
    children = [
        DocumentChild(
            info.filename, _read_part(archive, info, limits), {"package_part": info.filename}
        )
        for info in child_infos
        if info.file_size <= limits.max_single_child_bytes
    ]
    names = [info.filename for info in infos]
    obs: list[tuple[str, object]] = [
        ("ooxml.family", family),
        ("ooxml.content_types_present", True),
        ("ooxml.part_count", len(infos)),
        ("ooxml.relationship_count", len(relationships)),
        ("ooxml.external_relationships", external),
        ("ooxml.core_properties_present", "docProps/core.xml" in by_name),
        ("ooxml.application_properties_present", "docProps/app.xml" in by_name),
        ("ooxml.custom_properties_present", "docProps/custom.xml" in by_name),
        ("document.macro_enabled", macro),
        ("document.vba_project_present", any(name.endswith("vbaProject.bin") for name in names)),
        ("ooxml.embedded_object_count", len(child_infos)),
        ("ooxml.custom_xml_present", any(name.startswith("customXml/") for name in names)),
        (
            "ooxml.signature_parts_present",
            any(name.startswith("_xmlsignatures/") for name in names),
        ),
        ("ooxml.activex_present", any("activeX" in name for name in names)),
        (
            "ooxml.template_relationship_present",
            any("attachedTemplate" in rel.get("Type", "") for rel in external),
        ),
        ("ooxml.dde_structure_present", any("externalLink" in name for name in names)),
    ]
    for rel in external:
        obs.append(("document.external_relationship", rel))
        if "attachedTemplate" in rel.get("Type", ""):
            obs.append(("document.remote_template_reference", rel.get("Target")))
        if "hyperlink" in rel.get("Type", ""):
            obs.append(("document.hyperlink_target", rel.get("Target")))
    assessments: list[Assessment] = []
    if macro or any("activeX" in name for name in names):
        assessments.append(
            _assessment(
                "ACTIVE_CONTENT_PRESENT",
                "OOXML package contains macro or ActiveX structures",
                Confidence.HIGH,
                ["document.macro_enabled", "ooxml.activex_present"],
            )
        )
    if macro:
        assessments.append(
            _assessment(
                "MACRO_ENABLED_DOCUMENT",
                "OOXML content types or VBA project identify a macro-enabled document",
                Confidence.HIGH,
                ["document.macro_enabled"],
            )
        )
    if child_infos:
        assessments.append(
            _assessment(
                "EMBEDDED_OBJECT_PRESENT",
                "OOXML package contains meaningful embedded payload parts",
                Confidence.HIGH,
                ["ooxml.embedded_object_count"],
            )
        )
    if external:
        assessments.append(
            _assessment(
                "EXTERNAL_REFERENCE_PRESENT",
                "OOXML relationships contain external targets; none were fetched",
                Confidence.HIGH,
                ["ooxml.external_relationships"],
            )
        )
    return ParsedDocument(family, obs, assessments, children)


def _parse_odf(
    archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], limits: RuntimeSettings
) -> ParsedDocument:
    by_name = {info.filename: info for info in infos}
    mime = _read_part(archive, by_name["mimetype"], limits).decode("ascii", "replace").strip()
    fmt = {
        "application/vnd.oasis.opendocument.text": "ODF_ODT",
        "application/vnd.oasis.opendocument.spreadsheet": "ODF_ODS",
        "application/vnd.oasis.opendocument.presentation": "ODF_ODP",
    }.get(mime, "ODF")
    manifest = _safe_xml(_read_part(archive, by_name["META-INF/manifest.xml"], limits), limits)
    manifest_items = [dict(node.attrib) for node in manifest.iter()]
    encrypted = any(
        any("encryption-data" in key or "checksum" in key for key in item)
        for item in manifest_items
    )
    names = [info.filename for info in infos]
    embedded = [
        info
        for info in infos
        if (
            info.filename.startswith("Object ")
            or info.filename.startswith("ObjectReplacements/")
            or info.filename.startswith("Embedded/")
        )
        and not info.is_dir()
    ]
    children = [
        DocumentChild(
            info.filename, _read_part(archive, info, limits), {"package_part": info.filename}
        )
        for info in embedded
        if info.file_size <= limits.max_single_child_bytes
    ]
    external: list[str] = []
    scripts = any(name.startswith("Scripts/") or name.startswith("Basic/") for name in names)
    for name in ("content.xml", "styles.xml"):
        if name in by_name:
            root = _safe_xml(_read_part(archive, by_name[name], limits), limits)
            for node in root.iter():
                for key, value in node.attrib.items():
                    if key.endswith("}href") and re.match(r"(?i)^(?:https?|ftp):", value):
                        external.append(value[:MAX_STRING])
    obs = [
        ("odf.document_type", mime),
        ("odf.manifest_present", True),
        ("odf.metadata_present", "meta.xml" in by_name),
        ("odf.embedded_object_count", len(embedded)),
        ("odf.scripts_present", scripts),
        ("odf.external_links", external),
        ("odf.signature_present", any("documentsignatures.xml" in name for name in names)),
        ("odf.encryption_metadata_present", encrypted),
    ]
    assessments: list[Assessment] = []
    if scripts:
        assessments.append(
            _assessment(
                "ACTIVE_CONTENT_PRESENT",
                "ODF package contains script/macro structures",
                Confidence.HIGH,
                ["odf.scripts_present"],
            )
        )
    if embedded:
        assessments.append(
            _assessment(
                "EMBEDDED_OBJECT_PRESENT",
                "ODF package contains embedded object/file parts",
                Confidence.HIGH,
                ["odf.embedded_object_count"],
            )
        )
    if external:
        assessments.append(
            _assessment(
                "EXTERNAL_REFERENCE_PRESENT",
                "ODF XML contains external link values; none were fetched",
                Confidence.HIGH,
                ["odf.external_links"],
            )
        )
    if encrypted:
        assessments.append(
            _assessment(
                "ENCRYPTED_DOCUMENT",
                "ODF manifest contains encryption metadata; no password was attempted",
                Confidence.HIGH,
                ["odf.encryption_metadata_present"],
            )
        )
    return ParsedDocument(
        fmt,
        obs,
        assessments,
        children,
        ["ODF encryption metadata prevents complete content inspection"] if encrypted else [],
        "partial_unsupported" if encrypted else None,
    )


def _parse_rtf(data: bytes, limits: RuntimeSettings) -> ParsedDocument:
    signature = re.match(rb"\s*\{\\rtf(\d+)", data)
    if signature is None:
        raise DocumentError("invalid RTF signature")
    depth = maximum = 0
    escaped = False
    binary_remaining = 0
    anomaly: str | None = None
    for byte in data:
        if binary_remaining:
            binary_remaining -= 1
            continue
        if escaped:
            escaped = False
            continue
        if byte == 0x5C:
            escaped = True
        elif byte == 0x7B:
            depth += 1
            maximum = max(maximum, depth)
            if maximum > limits.max_rtf_group_depth:
                anomaly = "RTF nesting limit exceeded"
                break
        elif byte == 0x7D:
            depth -= 1
            if depth < 0:
                anomaly = "RTF unmatched closing group"
                break
    if anomaly is None and depth != 0:
        anomaly = "RTF unbalanced groups"
    words = [item.decode("ascii", "replace") for item in re.findall(rb"\\([A-Za-z]+)", data)]
    counts = Counter(words)
    urls = sorted({item.decode("utf-8", "replace")[:MAX_STRING] for item in URL.findall(data)})
    obs: list[tuple[str, object]] = [
        ("rtf.version", int(signature.group(1))),
        ("rtf.maximum_group_depth", maximum),
        ("rtf.control_word_count", len(words)),
        ("rtf.control_word_statistics", dict(counts.most_common(64))),
        ("rtf.font_table_present", "fonttbl" in counts),
        ("rtf.color_table_present", "colortbl" in counts),
        ("rtf.object_group_count", counts["object"]),
        ("rtf.objdata_present", "objdata" in counts),
        ("rtf.pict_present", "pict" in counts),
        ("rtf.field_present", "field" in counts),
        ("rtf.hyperlink_targets", urls),
        ("rtf.unicode_escape_count", counts["u"]),
        ("rtf.binary_declaration_count", counts["bin"]),
        ("rtf.structural_anomaly", anomaly),
    ]
    assessments: list[Assessment] = []
    if counts["object"] or counts["objdata"]:
        assessments.append(
            _assessment(
                "EMBEDDED_OBJECT_PRESENT",
                "RTF contains object/objdata structures",
                Confidence.HIGH,
                ["rtf.object_group_count", "rtf.objdata_present"],
            )
        )
    if urls:
        assessments.append(
            _assessment(
                "EXTERNAL_REFERENCE_PRESENT",
                "RTF contains URL values; none were fetched",
                Confidence.HIGH,
                ["rtf.hyperlink_targets"],
            )
        )
    errors = [anomaly] if anomaly else []
    if anomaly:
        assessments.append(
            _assessment(
                "DOCUMENT_STRUCTURE_ANOMALY", anomaly, Confidence.HIGH, ["rtf.structural_anomaly"]
            )
        )
    return ParsedDocument(
        "RTF",
        obs,
        assessments,
        errors=errors,
        partial="partial_limit"
        if "limit" in (anomaly or "")
        else "partial_error"
        if anomaly
        else None,
    )
