from __future__ import annotations

import json
import secrets
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from test_m14_containers import run_container
from test_m14b_disk_images import make_adf, make_lh0
from test_m16_documents import package_fixture

from avbox.application import ArtifactService
from avbox.config import RABCorrelationSettings
from avbox.correlation import (
    CorrelationService,
    HTTPRabCorrelationProvider,
    ReferenceRabCorrelationProvider,
    UnavailableRabCorrelationProvider,
)
from avbox.models import (
    AnalyzerResult,
    CorrelationErrorCode,
    CorrelationState,
    DerivedObject,
    ExactLookupState,
    ExactMatch,
    KnownOccurrence,
    Observation,
    ProvenanceRecord,
    QualificationState,
    RABObjectContext,
    Rights,
    RightsStatus,
    ScanJob,
    SimilarityCandidate,
    StructuralHistoryRecord,
    Verdict,
)

TOKEN = secrets.token_hex(32)


def artifact(tmp_path: Path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return ArtifactService.hash_file(path)


def known_match(item) -> ExactMatch:
    return ExactMatch(
        rab_object_id="rab:object:A",
        sha256=item.hashes.sha256,
        size=item.byte_size,
        context=RABObjectContext(
            rab_object_id="rab:object:A",
            sha256=item.hashes.sha256,
            size=item.byte_size,
            known_filenames=["A.bin", "<script>alert(1)</script>"],
            provenance=[
                ProvenanceRecord(source_label="Aminet CD 10"),
                ProvenanceRecord(source_label="physical CD dump"),
            ],
            rights=Rights(redistribution_rights=RightsStatus.UNKNOWN),
            physical_original_owned=True,
            metadata_urls=["http://127.0.0.1:9/must-not-be-fetched"],
            structural_validation_history=[
                StructuralHistoryRecord(state="VALID", validator="historical-avbox")
            ],
        ),
    )


def similarity_result(fingerprint: str, candidate) -> SimilarityCandidate:
    return SimilarityCandidate(
        algorithm="ssdeep",
        query_fingerprint=fingerprint,
        candidate_fingerprint="96:candidate:candidate",
        score=97,
        rab_object_id="rab:object:B",
        candidate_sha256=candidate.hashes.sha256,
        assessment="strong_candidate",
    )


def analyzer_with_ssdeep(fingerprint: str) -> AnalyzerResult:
    return AnalyzerResult(
        analyzer_id="similarity",
        analyzer_class="similarity_analyzer",
        product="ssdeep",
        completed_at=datetime.now(UTC),
        execution_profile="test",
        native_status="complete",
        qualification_state=QualificationState.QUALIFIED,
        observations=[
            Observation(
                observation_type="similarity.ssdeep",
                analyzer_id="similarity",
                value={"algorithm": "ssdeep", "fingerprint": fingerprint},
            )
        ],
    )


def test_exact_occurrences_provenance_rights_and_privacy(tmp_path: Path) -> None:
    item_a = artifact(tmp_path, "A.bin", b"A" * 4096)
    item_b = artifact(tmp_path, "B.bin", b"A" * 4095 + b"B")
    fingerprint = "96:query:query"
    provider = ReferenceRabCorrelationProvider(
        {item_a.hashes.sha256: known_match(item_a)},
        {
            item_a.hashes.sha256: [
                KnownOccurrence(
                    parent_rab_object_id="rab:cd:8",
                    relationship="MEMBER_OF",
                    logical_path="Utilities/Foo",
                ),
                KnownOccurrence(
                    parent_rab_object_id="rab:set:3", relationship="MEMBER_OF", logical_path="Foo"
                ),
            ]
        },
        {fingerprint: [similarity_result(fingerprint, item_b)]},
    )
    result = provider.correlate(item_a, fingerprint)
    assert result.exact.state == ExactLookupState.EXACT_MATCH
    assert len(result.known_occurrences) == 2
    context = result.exact.matches[0].context
    assert context and len(context.provenance) == 2
    assert context.physical_original_owned is True
    assert context.rights and context.rights.redistribution_rights == RightsStatus.UNKNOWN
    assert result.similarity.candidates[0].candidate_sha256 == item_b.hashes.sha256
    assert "bytes" not in provider.requests[0]
    assert provider.requests[0]["size"] == item_a.byte_size
    assert (
        context.metadata_urls and provider.requests == provider.requests
    )  # URL remains inert text.


def test_no_match_similarity_is_not_identity_or_security(tmp_path: Path) -> None:
    item_c = artifact(tmp_path, "C.bin", b"unrelated" * 500)
    item_b = artifact(tmp_path, "B.bin", b"related" * 500)
    fingerprint = "96:query:query"
    provider = ReferenceRabCorrelationProvider(
        {}, similarities={fingerprint: [similarity_result(fingerprint, item_b)]}
    )
    job = ScanJob(source="test", input_artifact=item_c, requested_scanners=[])
    job.normalized_verdict = Verdict.CLEAN
    job.analyzer_results = [analyzer_with_ssdeep(fingerprint)]
    CorrelationService(provider).process(job)
    result = job.preservation_context.correlation
    assert result and result.exact.state == ExactLookupState.NO_EXACT_MATCH
    assert result.similarity.candidates[0].score == 97
    assert job.normalized_verdict == Verdict.CLEAN


def test_child_match_attaches_without_changing_analysis_graph(tmp_path: Path) -> None:
    root = artifact(tmp_path, "root.zip", b"root-not-known")
    child = artifact(tmp_path, "child.bin", b"known-child")
    provider = ReferenceRabCorrelationProvider({child.hashes.sha256: known_match(child)})
    job = ScanJob(source="test", input_artifact=root, requested_scanners=[])
    job.derived_objects.append(
        DerivedObject(
            object=child,
            parent_sha256=root.hashes.sha256,
            depth=1,
            member_name="child.bin",
            extraction_status="EXTRACTED",
        )
    )
    CorrelationService(provider).process(job)
    assert job.preservation_context.correlation.exact.state == ExactLookupState.NO_EXACT_MATCH  # type: ignore[union-attr]
    child_result = job.derived_objects[0].preservation_context.correlation
    assert child_result and child_result.exact.state == ExactLookupState.EXACT_MATCH
    assert job.relationships == []


def test_real_retro_adf_lha_child_correlation_preserves_ancestry(tmp_path: Path) -> None:
    payload = b"M1.8 harmless known retro child\n" * 20
    source = tmp_path / "correlation.adf"
    make_adf(source, extra_entries={"KNOWN.LHA": make_lh0("known.bin", payload)})
    job = run_container(tmp_path, source, max_recursion_depth=3, use_bubblewrap=False)
    expected = artifact(tmp_path, "expected.bin", payload)
    known = next(
        child for child in job.derived_objects if child.object.sha256 == expected.hashes.sha256
    )
    provider = ReferenceRabCorrelationProvider(
        {known.object.sha256: known_match(expected)},
        {
            known.object.sha256: [
                KnownOccurrence(
                    parent_rab_object_id="rab:aminet-cd:8",
                    relationship="MEMBER_OF",
                    logical_path="Utilities/known.bin",
                )
            ]
        },
    )
    CorrelationService(provider).process(job)
    result = known.preservation_context.correlation
    assert result and result.exact.state == ExactLookupState.EXACT_MATCH
    assert known.depth == 2 and known.parent_sha256 != job.input_artifact.hashes.sha256
    assert any(edge.relationship == "FILESYSTEM_ENTRY_OF" for edge in job.relationships)
    assert any(
        edge.depth == 2 and edge.target_sha256 == known.object.sha256
        for edge in job.relationships
    )
    assert result.known_occurrences[0].authority == "RAB"


def test_real_ooxml_embedded_executable_context_coexists(tmp_path: Path) -> None:
    pe = b"MZ" + b"\0" * 510
    source = tmp_path / "embedded.docx"
    source.write_bytes(package_fixture("docx", embedded=pe))
    job = run_container(tmp_path, source)
    expected = artifact(tmp_path, "expected.exe", pe)
    child = next(
        item for item in job.derived_objects if item.object.sha256 == expected.hashes.sha256
    )
    child.analyzer_results.append(
        AnalyzerResult(
            analyzer_id="executable",
            analyzer_class="executable_analyzer",
            product="AVBox executable parser",
            completed_at=datetime.now(UTC),
            execution_profile="read-only",
            native_status="complete",
            qualification_state=QualificationState.QUALIFIED,
        )
    )
    CorrelationService(
        ReferenceRabCorrelationProvider({child.object.sha256: known_match(expected)})
    ).process(job)
    assert child.preservation_context.correlation.exact.state == ExactLookupState.EXACT_MATCH  # type: ignore[union-attr]
    assert child.analyzer_results[0].analyzer_id == "executable"
    assert any(edge.relationship == "EMBEDDED_FILE_OF" for edge in job.relationships)


def test_unavailable_and_budget_do_not_fail_job(tmp_path: Path) -> None:
    root = artifact(tmp_path, "root.bin", b"root")
    child = artifact(tmp_path, "child.bin", b"child")
    job = ScanJob(source="test", input_artifact=root, requested_scanners=[])
    job.normalized_verdict = Verdict.CLEAN
    job.derived_objects.append(
        DerivedObject(
            object=child,
            parent_sha256=root.hashes.sha256,
            depth=1,
            extraction_status="EXTRACTED",
        )
    )
    CorrelationService(UnavailableRabCorrelationProvider(), max_objects=1).process(job)
    assert job.preservation_context.correlation.state == CorrelationState.UNAVAILABLE  # type: ignore[union-attr]
    skipped = job.derived_objects[0].preservation_context.correlation
    assert skipped and skipped.state == CorrelationState.PARTIAL
    assert "max_correlated_objects" in str(skipped.skipped_reason)
    assert job.normalized_verdict == Verdict.CLEAN


class QualificationHandler(BaseHTTPRequestHandler):
    response_document: dict[str, object] = {}
    mode = "valid"
    observed: dict[str, object] = {}

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).observed = {"authorization": self.headers.get("Authorization"), "body": body}
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401)
            self.end_headers()
            return
        if type(self).mode == "timeout":
            time.sleep(0.2)
        self.send_response(200)
        self.end_headers()
        if type(self).mode == "malformed":
            self.wfile.write(b"not-json")
        elif type(self).mode == "oversized":
            self.wfile.write(b"{" + b"x" * 16384)
        else:
            self.wfile.write(json.dumps(type(self).response_document).encode())

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@pytest.fixture
def loopback_server():
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), QualificationHandler)
    except PermissionError:
        pytest.skip("local sandbox prohibits loopback sockets; exercised on qualification VM")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join()


def http_provider(tmp_path: Path, server: ThreadingHTTPServer, **values: object):
    credential = tmp_path / "rab-correlation-token"
    credential.write_text(str(values.pop("token", TOKEN)), encoding="utf-8")
    credential.chmod(0o600)
    settings = RABCorrelationSettings(
        enabled=True,
        endpoint=f"http://127.0.0.1:{server.server_port}",
        credential_file=credential,
        request_timeout_seconds=values.pop("request_timeout_seconds", 1),
        maximum_response_bytes=values.pop("maximum_response_bytes", 8192),
        **values,
    )
    return HTTPRabCorrelationProvider(settings)


def test_real_loopback_transport_auth_request_shape_and_conflict(
    tmp_path: Path, loopback_server: ThreadingHTTPServer
) -> None:
    item = artifact(tmp_path, "A.bin", b"A" * 4096)
    valid = ReferenceRabCorrelationProvider({item.hashes.sha256: known_match(item)}).correlate(
        item, None
    )
    QualificationHandler.mode = "valid"
    QualificationHandler.response_document = valid.model_dump(mode="json")
    provider = http_provider(tmp_path, loopback_server)
    result = provider.correlate(item, None)
    assert result.exact.state == ExactLookupState.EXACT_MATCH
    request = json.loads(QualificationHandler.observed["body"])
    assert request["object"]["sha256"] == item.hashes.sha256
    assert request["object"]["size"] == item.byte_size
    assert "bytes" not in request and "url" not in request
    conflict = valid.model_copy(deep=True)
    conflict.exact.matches[0].size += 1
    QualificationHandler.response_document = conflict.model_dump(mode="json")
    result = provider.correlate(item, None)
    assert result.errors == [CorrelationErrorCode.RAB_IDENTITY_CONFLICT]


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("malformed", CorrelationErrorCode.RAB_PROTOCOL_ERROR),
        ("oversized", CorrelationErrorCode.RAB_RESPONSE_TOO_LARGE),
        ("timeout", CorrelationErrorCode.RAB_TIMEOUT),
    ],
)
def test_loopback_transport_failure_bounds(
    tmp_path: Path,
    loopback_server: ThreadingHTTPServer,
    mode: str,
    expected: CorrelationErrorCode,
) -> None:
    item = artifact(tmp_path, "input.bin", b"input")
    QualificationHandler.mode = mode
    provider = http_provider(
        tmp_path,
        loopback_server,
        request_timeout_seconds=0.05 if mode == "timeout" else 1,
    )
    result = provider.correlate(item, None)
    assert result.errors == [expected]
    assert result.state == CorrelationState.ERROR


def test_loopback_auth_failure_is_redacted(
    tmp_path: Path, loopback_server: ThreadingHTTPServer
) -> None:
    item = artifact(tmp_path, "input.bin", b"input")
    QualificationHandler.mode = "valid"
    rejected_token = TOKEN[::-1]
    provider = http_provider(tmp_path, loopback_server, token=rejected_token)
    result = provider.correlate(item, None)
    assert result.errors == [CorrelationErrorCode.RAB_AUTH_FAILED]
    assert rejected_token not in result.model_dump_json()
