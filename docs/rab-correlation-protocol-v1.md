# AVBox to RAB Correlation Protocol v1

This is the read-only AVBox -> RAB direction, distinct from the RAB -> AVBox
analysis submission contract in `rab-protocol-v1.md`.

The client posts JSON to the server-configured `POST /v1/correlate` endpoint
with `protocol_version: "1"`. Analysis callers cannot choose the endpoint and
redirects are not followed. Production transport uses HTTPS and a service
bearer credential outside Git; loopback HTTP is permitted for qualification.
Credential files must have no group/other permission bits and secrets are not
included in results or logs.

`RabCorrelationProvider` exposes `exact_lookup`, `hash_lookup`,
`similarity_candidates`, `relationships`, `object_context`, and combined
`correlate`. A future transport can replace HTTP without changing analysis.

## Request

```json
{
  "protocol_version": "1",
  "object": {
    "sha256": "...", "blake3": "...", "sha1": "...", "md5": "...",
    "size": 1234
  },
  "similarity": {"algorithm": "ssdeep", "fingerprint": "..."}
}
```

SHA-256 and size are mandatory. Filename and bytes are not sent. Similarity is
omitted when unavailable or budget-exhausted. Additional hashes can aid lookup
but cannot establish exact identity when SHA-256 disagrees.

## Response and semantics

The typed result has provider identity/version, overall state, exact matches,
independent similarity completeness, RAB occurrences, warnings, and errors.
Exact states are `EXACT_MATCH`, `NO_EXACT_MATCH`, `RAB_UNAVAILABLE`, and
`ERROR`. Completeness uses `NOT_REQUESTED`, `UNAVAILABLE`, `COMPLETE`, `PARTIAL`,
or `ERROR`.

Exact records carry stable RAB ID, SHA-256, size and optional filenames,
collections, multiple provenance records, rights, physical-original ownership,
preservation status, and historical structural validation. Occurrences carry a
parent RAB ID, relationship, and logical path. These RAB-authority facts never
become AVBox extraction edges.

Similarity candidates carry algorithm, both fingerprints, score, candidate RAB
ID and candidate SHA-256. A candidate is never exact identity, deduplication, or
a security verdict, regardless of score.

## Errors and bounds

Stable errors are `RAB_UNAVAILABLE`, `RAB_TIMEOUT`, `RAB_AUTH_FAILED`,
`RAB_PROTOCOL_ERROR`, `RAB_RESPONSE_TOO_LARGE`, and `RAB_IDENTITY_CONFLICT`.
Connection/request time, response bytes, record counts and strings are bounded.
An exact SHA-256 or size inconsistency rejects the response as an identity
conflict.

Remote strings and URL-looking values are inert untrusted metadata. AVBox does
not render them as HTML, execute them, or retrieve returned URLs. Correlation
failure does not change security verdicts, structural validation, or ordinary
job success.
