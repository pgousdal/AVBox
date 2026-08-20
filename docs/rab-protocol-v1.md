# RAB Protocol v1 wire contract

RAB Protocol v1 is AVBox's authenticated, asynchronous machine interface for analysis of digital objects. It is not a virus-scan-only API. The namespace is `/api/v1/rab`; the protocol value is `1`.

## Authentication and authorization

Every endpoint requires `Authorization: Bearer TOKEN`. Tokens map server-side to a fixed `client_id` and scopes: `analysis.submit`, `analysis.read`, and `capabilities.read`. Comparison is constant-time. Credentials live in `/etc/avbox/rab-clients.json`, mode 0640, outside Git. Rotate by atomically replacing the external token file and rerunning Ansible; tokens are never logged.

Default binding remains `127.0.0.1`. A separate-host deployment must explicitly enable LAN binding and should add TLS or a mutually authenticated reverse proxy.

## Endpoints

- `GET /api/v1/rab/capabilities`
- `GET /api/v1/rab/analysis-profiles`
- `POST /api/v1/rab/analysis-jobs`
- `GET /api/v1/rab/analysis-jobs/{job_id}`
- `GET /api/v1/rab/analysis-jobs/{job_id}/results`

Submission is multipart form data with `object_bytes`, `client_request_id`, `expected_sha256`, `profile`, `protocol_version`, and optional filename/media type. `Idempotency-Key` is required. The filename is untrusted metadata and never selects a path.

Example:

```sh
curl -H "Authorization: Bearer $AVBOX_RAB_TOKEN" \
  -H "Idempotency-Key: rab-request-123" \
  -F protocol_version=1 \
  -F client_request_id=rab-request-123 \
  -F profile=security-default@1 \
  -F expected_sha256=012345... \
  -F object_bytes=@object.bin \
  http://127.0.0.1:8080/api/v1/rab/analysis-jobs
```

Success returns HTTP 202 and a UUID job ID. An identical retry returns HTTP 200 and the same job with `duplicate=true`. Conflicting key reuse returns 409 `IDEMPOTENCY_CONFLICT`.

## Semantic result layers

- **Observation:** objective fact, such as hash, size, format, or future container member count.
- **Finding:** native detector/rule/validator report.
- **Assessment:** evidence-based interpretation with source, evidence references, and optional confidence.
- **Verdict:** optional normalized security judgment. Non-security analyzers need not provide one.
- **Preservation context:** RAB correlation/provenance/recommendation fields. Correlation is currently `NOT_AVAILABLE`.

`CLEAN` does not mean safe. High entropy or packing does not mean malicious. A YARA match is not automatically malicious. Corruption is not malware. UNKNOWN and analyzer failures are never CLEAN.

Raw output is returned only as an opaque ID plus SHA-256, size, and `text/plain` media type. No filesystem path or raw content is returned.

## Errors

Errors contain `protocol_version`, stable `code`, and human-readable `detail`. Codes are: `INVALID_REQUEST`, `UNSUPPORTED_PROTOCOL_VERSION`, `AUTHENTICATION_REQUIRED`, `FORBIDDEN`, `OBJECT_HASH_MISMATCH`, `OBJECT_TOO_LARGE`, `UNSUPPORTED_PROFILE`, `IDEMPOTENCY_CONFLICT`, `QUEUE_FULL`, `ANALYZER_UNAVAILABLE`, `ANALYSIS_FAILED`, `STORAGE_UNAVAILABLE`, `INTERNAL_ERROR`, and `NOT_FOUND`.

## Versioning and schemas

OpenAPI is available at `/openapi.json`. Core Pydantic schema snapshots are tested. Material profile changes require a new version, such as `security-default@2`; existing `@1` behavior remains reproducible. A future protocol v2 uses a new namespace/contract without changing v1.

## M1.2 identification profile example

`identification-default@1` contains `identity`, `basic-metadata`, and
`file-type`. `security-default@1` remains unchanged. A representative result is:

```json
{
  "profile": "identification-default@1",
  "object": {"filename": "invoice.pdf.exe", "sha256": "…", "size": 128},
  "observations": [
    {"observation_type": "filename.extensions", "value": ["pdf", "exe"], "analyzer_id": "basic-metadata"},
    {"observation_type": "file.mime.type", "value": "application/vnd.microsoft.portable-executable", "analyzer_id": "file-type"}
  ],
  "assessments": [
    {"assessment_type": "FILE_TYPE", "statement": "family=executable; format=PE", "confidence": "HIGH", "analyzer_id": "file-type"},
    {"assessment_type": "MULTIPLE_EXTENSION", "statement": "filename has multiple non-compound suffix components", "confidence": "HIGH", "analyzer_id": "basic-metadata"}
  ],
  "verdict": null
}
```

The schema can retain conflicting extension, declared-MIME, and libmagic
evidence. None of those disagreements independently creates a security verdict.

## M1.3 static profile

`static-default@1` adds `strings`, `byte-statistics`, `generic-metadata`, and
`similarity` to the unchanged M1.2 identity/type analyzers. It returns facts
such as `strings.value`, `byte.entropy.shannon`, namespaced
`metadata.exiftool.*`, and `similarity.ssdeep`. A static-only result normally
has `verdict: null`. The profile analyzes only the outer object: ZIP, LHA, or
ISO recognition does not enumerate or extract children. TLSH is not advertised
because its Debian 13 packaging is deferred.
