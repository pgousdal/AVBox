# M1.4 Safe Container and Recursive Object Analysis

M1.4 discovers byte-bearing derivatives from a submitted outer object. It
uses Python's standard-library userspace handlers for ZIP, tar, gzip, bzip2,
and xz. No archive is mounted, no kernel filesystem is traversed, and no
member is executed. 7z, ISO, LHA/LZX, disk images, and retro filesystems are
deferred to later milestones.

## Object graph

Every materialized child is independently hashed (SHA-256, BLAKE3, SHA-1,
and MD5). The parent remains the immutable submitted object. Protocol v1
returns `derived_objects` and `relationships`; relationships carry the parent
and child SHA-256, untrusted member name, normalized display name, analyzer,
depth, and member index. `CONTAINS` is used for archive members and
`DECOMPRESSED_FROM` for a gzip/bzip2/xz stream. Duplicate content may share
one identity while retaining each membership edge.

Extracted bytes are transient analysis derivatives. Rights are not inherited
and default to `unknown`; AVBox does not write them to RAB automatically.
Security-positive children may be admitted to the existing content-addressed
quarantine with their relationship chain.

## Budgets and completeness

The server-wide defaults are configured under `runtime`:

| Budget | Default |
| --- | ---: |
| recursion depth | 3 |
| children per object | 100 |
| children per job | 1,000 |
| single child | 64 MiB |
| total extracted bytes | 512 MiB |
| expansion ratio | 100x |
| member-name bytes | 4,096 |
| path depth | 32 |
| extraction time | 300 seconds |

The counters are global to the recursive job, not reset for each level.
Limits produce neutral events such as `CHILD_SIZE_LIMIT`,
`EXTRACTION_BYTE_BUDGET_EXHAUSTED`, `EXPANSION_RATIO_LIMIT`, and
`RECURSION_LIMIT_REACHED`. They set completeness to `PARTIAL_LIMIT`; they do
not create a malware verdict. `PARTIAL_ERROR`, `PARTIAL_ENCRYPTED`, and
`PARTIAL_UNSUPPORTED` are reserved for corresponding parser outcomes.

## Path and entry safety

Member names are metadata only. Absolute paths, drive paths, traversal,
mixed separators, excessive depth, and NUL-containing names are rejected
without being used as host paths. Tar symlinks, hardlinks, device nodes,
FIFOs, sockets, ownership, permissions, and timestamps are never applied or
followed. Encrypted ZIP entries are reported as unavailable; passwords are
never guessed. CRCs may be checked by the parser, but child identity always
comes from AVBox hashes.

Extraction runs in the unprivileged, no-network AVBox worker under the same
systemd/bubblewrap boundary used by current analyzers, with read-only input,
dedicated transient output, streaming size checks, timeout and output
budgets. The API process never accepts a host path or URL for extraction.

## Recursive profiles

`recursive-default@1` combines the stable identification, static, and
security analyzers with the `container` analyzer. Existing
`identification-default@1`, `static-default@1`, and `security-default@1` are
unchanged. Child analysis reuses those analyzers; the container analyzer is
not recursively invoked after the configured depth limit.

The aggregate security verdict is conservative: a malicious/PUA/suspicious
child can elevate the recursive job result, while the root analyzer results,
child results, and relationship chain remain separate. Safety limits,
corruption, encryption, and unusual names never become malware verdicts.

