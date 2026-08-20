# M1.1 RAB analysis-job foundation

## Ownership boundary

RAB owns preservation, archival identity, acquisition provenance, cataloguing, and long-term bytes. AVBox owns analysis, detection, validation, assessment, and temporary security quarantine. AVBox upload staging is transient and quarantine is containment—not a second archive.

## Intake and identity

The server reads multipart uploads in 1 MiB chunks into a generated mode-0400 path, enforces the configured maximum while streaming, calculates SHA-256/BLAKE3/SHA-1/MD5, fsyncs, and verifies expected SHA-256 before creating a job. It never uses a filename as a path, executes bytes, mounts them, or unpacks them. Arbitrary URLs, URI schemes, and host paths are not accepted.

External references can be represented as future metadata, but `reference_resolution` is `NOT_IMPLEMENTED`; there is no SSRF-capable fetcher or local-file broker.

## Queue and persistence

The existing `ScanJob` UUID and state machine remain authoritative. RAB provenance/idempotency records reference that same job in SQLite. A bounded in-process queue feeds configurable worker threads. Capacity rejection is HTTP 429 `QUEUE_FULL`. Jobs accepted into SQLite survive restart; startup changes stale RAB STAGED/QUEUED/RUNNING jobs to FAILED with an interruption error, avoiding phantom RUNNING and accidental duplicate execution.

Idempotency is scoped by authenticated client. Only SHA-256 of the idempotency key is persisted. Its semantic fingerprint includes client ID, client request ID, object SHA-256, and versioned profile.

## Profiles and analyzers

Profiles are Git-versioned in `config/analysis-profiles.yaml`. `security-default@1` contains only qualified object analyzers ClamAV and YARA. chkrootkit/rkhunter remain system-only. Deferred analyzers are not advertised operationally.

The envelope reserves typed child relationships (`CONTAINS`, `EMBEDS`, `EXTRACTED_FROM`, `DERIVED_FROM`, `REPAIRED_FROM`, `SIMILAR_TO`, `DUPLICATE_OF`) and generic analyzer classes without implementing extraction or M1.2 analyzers.

## Lifecycle

Clean: retain job/results and delete uploaded/staging bytes. MALICIOUS/SUSPICIOUS/PUA: copy to immutable quarantine CAS according to AVBox policy, then remove upload staging. No automatic RAB upload or permanent general retention occurs.
