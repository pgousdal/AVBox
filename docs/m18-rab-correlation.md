# M1.8 Similarity, Correlation and RAB Object Intelligence

M1.8 connects AVBox identities and object graphs to read-only preservation
intelligence. RAB remains preservation authority; AVBox remains analysis and
correlation consumer. No ingest, metadata/rights mutation, relationship
writeback, content retrieval, or object-byte upload is implemented.

`RabCorrelationProvider` separates analysis from transport. The production HTTP
provider implements RAB Correlation Protocol v1. The deterministic
`avbox-m18-reference-provider` is explicitly non-production. Without a configured
endpoint, production status is `NOT_AVAILABLE`; an unavailable result is
attached while analysis completes normally.

`CorrelationService` processes root then children in deterministic graph order,
bounded by object count, similarity-query count and total deadline. Skipped
objects carry `PARTIAL` and a reason. Child results attach to that child's typed
`preservation_context`; AVBox ancestry and RAB occurrences remain separate.

- SHA-256 plus consistent size is exact identity. Names/fuzzy hashes are not.
- ssdeep returns candidates and never deduplicates or creates security verdicts.
- Rights are preserved. Exact identity, public URL and physical ownership do not
  imply redistribution permission.
- Multiple provenance records remain distinct.
- Historical RAB validation does not replace the current M1.7 result.
- Disagreement is represented; SHA-256/size inconsistency is an identity error.

The opt-in `correlation-default@1` profile combines identity, file type,
similarity, recursion and correlation. `avbox correlate FILE` is its shortcut;
`avbox rab-correlation status` reports capability truth. Existing profiles do
not acquire a RAB dependency.

Debian 13 now offers `python3-tlsh`/`libtlsh-dev`, unlike the M1.3 survey. TLSH
integration and semantic qualification remain deferred because M1.8 requires
only the already-qualified ssdeep path; no unused or upstream dependency is added.
