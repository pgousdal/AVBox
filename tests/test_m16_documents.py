from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib
from pathlib import Path

import pytest
from test_m14_containers import run_container, settings

from avbox.analyzers.document import DocumentAnalyzer, DocumentError, parse_document
from avbox.application.artifacts import ArtifactService


def write_fixture(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def pdf_fixture(*, embedded: bytes | None = None, eof: bool = True) -> bytes:
    payload = zlib.compress(embedded) if embedded is not None else b""
    embedded_object = (
        b"5 0 obj\n<< /Type /EmbeddedFile /Filter /FlateDecode /Length "
        + str(len(payload)).encode()
        + b" >>\nstream\n"
        + payload
        + b"\nendstream\nendobj\n"
        if embedded is not None
        else b""
    )
    return (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 6 0 R >> "
        b"/OpenAction << /S /JavaScript /JS (app.alert harmless) >> "
        b"/AA << /O << /S /URI /URI (http://127.0.0.1:9/not-fetched) >> >> >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Metadata 7 0 R /AcroForm << /XFA [] >> /Sig 8 0 R >>\nendobj\n"
        + embedded_object
        + b"7 0 obj\n<< /Type /Metadata >>\nstream\n"
        b"<x:xmpmeta application/rdf+xml/>\nendstream\nendobj\n"
        b"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\nstartxref\n0\n"
        + (b"%%EOF\n" if eof else b"")
    )


def _directory_entry(
    name: str,
    kind: int,
    start: int,
    size: int,
    *,
    right: int = 0xFFFFFFFF,
    child: int = 0xFFFFFFFF,
) -> bytes:
    raw = bytearray(128)
    encoded = (name + "\0").encode("utf-16le")
    raw[: len(encoded)] = encoded
    struct.pack_into("<HBBIII", raw, 64, len(encoded), kind, 1, 0xFFFFFFFF, right, child)
    struct.pack_into("<I", raw, 116, start)
    struct.pack_into("<Q", raw, 120, size)
    return bytes(raw)


def cfb_fixture(*, package: bytes | None = None) -> bytes:
    source = b'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\nEnd Sub\r\n'
    compressed_source = b"\x01" + struct.pack("<H", 0x3000 | (len(source) - 1)) + source
    streams = [
        ("WordDocument", b"harmless legacy document"),
        ("dir", b"VBA directory"),
        ("Module1", compressed_source),
        ("\x05SummaryInformation", b"summary"),
    ]
    if package is not None:
        streams.append(("Package", package))
    directory_sectors = (len(streams) + 1 + 3) // 4
    stream_chains: list[list[int]] = []
    next_sid = directory_sectors
    for _, value in streams:
        count = max(1, (len(value) + 511) // 512)
        stream_chains.append(list(range(next_sid, next_sid + count)))
        next_sid += count
    fat_sid = next_sid
    header = bytearray(512)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HH", header, 24, 0x003E, 3)
    struct.pack_into("<HH", header, 28, 0xFFFE, 9)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<I", header, 48, 0)
    struct.pack_into("<I", header, 56, 0)
    struct.pack_into("<I", header, 60, 0xFFFFFFFE)
    struct.pack_into("<I", header, 68, 0xFFFFFFFE)
    struct.pack_into("<109I", header, 76, fat_sid, *([0xFFFFFFFF] * 108))
    entries = [_directory_entry("Root Entry", 5, 0xFFFFFFFE, 0, child=1)]
    for index, (name, value) in enumerate(streams):
        entries.append(
            _directory_entry(
                name,
                2,
                stream_chains[index][0],
                len(value),
                right=index + 2 if index + 1 < len(streams) else 0xFFFFFFFF,
            )
        )
    directory = b"".join(entries).ljust(directory_sectors * 512, b"\0")
    sectors = [directory[index : index + 512] for index in range(0, len(directory), 512)]
    for _, value in streams:
        padded = value.ljust(((len(value) + 511) // 512 or 1) * 512, b"\0")
        sectors.extend(padded[index : index + 512] for index in range(0, len(padded), 512))
    fat = [0xFFFFFFFF] * 128
    for sid in range(directory_sectors):
        fat[sid] = sid + 1 if sid + 1 < directory_sectors else 0xFFFFFFFE
    for chain in stream_chains:
        for index, sid in enumerate(chain):
            fat[sid] = chain[index + 1] if index + 1 < len(chain) else 0xFFFFFFFE
    fat[fat_sid] = 0xFFFFFFFD
    sectors.append(struct.pack("<128I", *fat))
    return bytes(header) + b"".join(sectors)


def package_fixture(
    family: str,
    *,
    macro: bool = False,
    embedded: bytes | None = None,
    external: str | None = None,
    relationship_xml: bytes | None = None,
) -> bytes:
    roots = {"docx": "wordprocessingml", "xlsx": "spreadsheetml", "pptx": "presentationml"}
    prefixes = {"docx": "word", "xlsx": "xl", "pptx": "ppt"}
    root = roots[family]
    prefix = prefixes[family]
    content_type = f"application/vnd.openxmlformats-officedocument.{root}.main+xml"
    if macro:
        content_type = f"application/vnd.ms-office.{root}.macroEnabled.main+xml"
    content = (
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'<Override PartName="/{prefix}/main.xml" ContentType="{content_type}"/></Types>'
    )
    rel = (
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + (
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            f'relationships/hyperlink" Target="{external}" TargetMode="External"/>'
            if external
            else ""
        )
        + "</Relationships>"
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content)
        archive.writestr("_rels/.rels", relationship_xml or rel)
        archive.writestr("docProps/core.xml", "<coreProperties/>")
        archive.writestr("docProps/app.xml", "<Properties/>")
        archive.writestr(f"{prefix}/main.xml", "<document/>")
        if embedded is not None:
            archive.writestr(f"{prefix}/embeddings/payload.bin", embedded)
        if macro:
            archive.writestr(f"{prefix}/vbaProject.bin", cfb_fixture())
    return output.getvalue()


def odt_fixture(*, external: str | None = None) -> bytes:
    href = f' xlink:href="{external}"' if external else ""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        archive.writestr(
            "META-INF/manifest.xml",
            '<manifest:manifest '
            'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>'
        )
        archive.writestr(
            "content.xml",
            '<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            f'xmlns:xlink="http://www.w3.org/1999/xlink"><office:a{href}/></office:document>',
        )
        archive.writestr("meta.xml", "<meta/>")
    return output.getvalue()


def observations(parsed: object) -> dict[str, object]:
    return dict(parsed.observations)  # type: ignore[attr-defined]


def test_pdf_structure_metadata_actions_embedding_and_malformed(tmp_path: Path) -> None:
    embedded = package_fixture("docx", embedded=b"plain child")
    source = write_fixture(tmp_path, "fixture.pdf", pdf_fixture(embedded=embedded))
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    parsed = parse_document(source, settings(tmp_path).runtime)
    assert parsed and parsed.format == "PDF"
    values = observations(parsed)
    assert values["pdf.version"] == "1.7"
    assert values["pdf.page_count"] == 1
    assert values["pdf.metadata_present"] and values["pdf.xmp_present"]
    assert values["pdf.names_tree_present"] and values["pdf.javascript_action_present"]
    assert values["pdf.open_action_present"] and values["pdf.additional_actions_present"]
    assert values["pdf.uri_action_present"] and values["pdf.acroform_present"]
    assert values["pdf.xfa_present"] and values["pdf.signature_structure_present"]
    assert values["pdf.xref_table_present"] and values["pdf.trailer_present"]
    assert parsed.children[0].data == embedded
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    malformed = write_fixture(tmp_path, "truncated.pdf", pdf_fixture(eof=False))
    partial = parse_document(malformed, settings(tmp_path).runtime)
    assert partial and partial.partial == "partial_error"
    encrypted = write_fixture(
        tmp_path,
        "encrypted.pdf",
        pdf_fixture().replace(b"/Pages 2 0 R", b"/Pages 2 0 R /Encrypt 9 0 R"),
    )
    protected = parse_document(encrypted, settings(tmp_path).runtime)
    assert protected and protected.partial == "partial_unsupported"
    assert observations(protected)["pdf.encryption_present"]
    assert "DOCUMENT_STRUCTURE_ANOMALY" not in {
        item.assessment_type for item in protected.assessments
    }


def test_cfb_hierarchy_vba_autoopen_and_embedded_package(tmp_path: Path) -> None:
    payload = package_fixture("xlsx")
    source = write_fixture(tmp_path, "fixture.doc", cfb_fixture(package=payload))
    parsed = parse_document(source, settings(tmp_path).runtime)
    assert parsed and parsed.format == "OLE_DOC"
    values = observations(parsed)
    assert values["cfb.sector_size"] == 512 and values["cfb.mini_sector_size"] == 64
    assert values["cfb.directory_hierarchy"]
    assert values["cfb.summary_information_present"]
    assert values["document.vba_project_present"]
    assert values["document.vba_module_count"] == 1
    assert values["document.vba_auto_entry_points"] == ["AutoOpen"]
    assert parsed.children[0].data == payload
    with pytest.raises(DocumentError, match="truncated"):
        parse_document(
            write_fixture(tmp_path, "bad.doc", cfb_fixture()[:200]), settings(tmp_path).runtime
        )


@pytest.mark.parametrize(
    ("family", "expected"),
    [("docx", "OOXML_DOCX"), ("xlsx", "OOXML_XLSX"), ("pptx", "OOXML_PPTX")],
)
def test_ooxml_families_relationships_and_properties(
    tmp_path: Path, family: str, expected: str
) -> None:
    target = "http://127.0.0.1:9/not-fetched"
    source = write_fixture(tmp_path, f"fixture.{family}", package_fixture(family, external=target))
    parsed = parse_document(source, settings(tmp_path).runtime)
    assert parsed and parsed.format == expected
    values = observations(parsed)
    assert values["ooxml.content_types_present"]
    assert values["ooxml.core_properties_present"]
    assert values["ooxml.application_properties_present"]
    assert values["ooxml.external_relationships"][0]["Target"] == target


def test_macro_ooxml_vba_child_and_recursive_embedded_pe(tmp_path: Path) -> None:
    macro = write_fixture(tmp_path, "fixture.docm", package_fixture("docx", macro=True))
    parsed = parse_document(macro, settings(tmp_path).runtime)
    assert parsed and parsed.format == "OOXML_DOCM"
    assert observations(parsed)["document.vba_project_present"]
    assert parsed.children[0].data.startswith(b"\xd0\xcf\x11\xe0")
    pe = b"MZ" + b"\0" * 62
    embedded = write_fixture(tmp_path, "embedded.docx", package_fixture("docx", embedded=pe))
    job = run_container(tmp_path, embedded)
    assert job.relationships[0].relationship == "EMBEDDED_FILE_OF"
    child = job.derived_objects[0]
    assert child.object.sha256 == hashlib.sha256(pe).hexdigest()
    assert child.parent_sha256 == job.input_artifact.hashes.sha256
    assert child.object.size == len(pe) and child.depth == 1
    assert child.metadata["package_part"] == "word/embeddings/payload.bin"


def test_xml_dtd_depth_component_attribute_and_expanded_limits(tmp_path: Path) -> None:
    bad = package_fixture(
        "docx",
        relationship_xml=b"<!DOCTYPE x [<!ENTITY e SYSTEM 'http://127.0.0.1:9/x'>]>"
        b"<Relationships><Relationship Target='&e;'/></Relationships>",
    )
    with pytest.raises(DocumentError, match="DTD/entity"):
        parse_document(write_fixture(tmp_path, "xxe.docx", bad), settings(tmp_path).runtime)
    deep = ("<x>" * 6 + "</x>" * 6).encode()
    archive = package_fixture("docx", relationship_xml=deep)
    with pytest.raises(DocumentError, match="nesting"):
        parse_document(
            write_fixture(tmp_path, "deep.docx", archive),
            settings(tmp_path, max_document_xml_depth=4).runtime,
        )
    with pytest.raises(DocumentError, match="expanded-size"):
        parse_document(
            write_fixture(tmp_path, "large.docx", package_fixture("docx", embedded=b"A" * 5000)),
            settings(tmp_path, max_document_parser_bytes=4096).runtime,
        )


def test_rtf_structure_unicode_object_url_malformed_and_depth(tmp_path: Path) -> None:
    data = br"{\rtf1{\fonttbl{\f0 Arial;}}\uc1\u65?{\object{\objdata 4142}}{\field http://127.0.0.1:9/no}}"
    source = write_fixture(tmp_path, "fixture.rtf", data)
    parsed = parse_document(source, settings(tmp_path).runtime)
    assert parsed and parsed.format == "RTF"
    values = observations(parsed)
    assert values["rtf.maximum_group_depth"] >= 3
    assert values["rtf.unicode_escape_count"] == 1
    assert values["rtf.object_group_count"] == 1 and values["rtf.objdata_present"]
    assert values["rtf.field_present"] and values["rtf.hyperlink_targets"]
    malformed = parse_document(
        write_fixture(tmp_path, "broken.rtf", br"{\rtf1{broken}"), settings(tmp_path).runtime
    )
    assert malformed and malformed.partial == "partial_error"
    limited = parse_document(
        write_fixture(tmp_path, "deep.rtf", br"{\rtf1{{{{{x}}}}}}"),
        settings(tmp_path, max_rtf_group_depth=3).runtime,
    )
    assert limited and limited.partial == "partial_limit"


def test_odt_package_is_recognized_without_fetching(tmp_path: Path) -> None:
    source = write_fixture(
        tmp_path, "fixture.odt", odt_fixture(external="http://127.0.0.1:9/not-fetched")
    )
    parsed = parse_document(source, settings(tmp_path).runtime)
    assert parsed and parsed.format == "ODF_ODT"
    values = observations(parsed)
    assert values["odf.manifest_present"] and values["odf.metadata_present"]
    assert values["odf.external_links"] == ["http://127.0.0.1:9/not-fetched"]


def test_document_analyzer_keeps_assessments_out_of_verdict(tmp_path: Path) -> None:
    source = write_fixture(tmp_path, "active.pdf", pdf_fixture())
    artifact = ArtifactService.hash_file(source)
    result = DocumentAnalyzer(settings(tmp_path).runtime).analyze(artifact, source, "job")
    assert result.native_status == "complete"
    assert {item.assessment_type for item in result.assessments} >= {
        "ACTIVE_CONTENT_PRESENT",
        "EXTERNAL_REFERENCE_PRESENT",
    }
    assert result.findings == []
    assert result.normalized_verdict is None
