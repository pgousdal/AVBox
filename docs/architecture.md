# Architecture

M1.8 adds a transport-independent `RabCorrelationProvider` behind an optional
correlation service. RAB facts live in typed preservation context and never
overwrite AVBox observations, verdicts, structural validation, or relationships.
Root and children are correlated in deterministic bounded order after discovery.

AVBox has three boundaries: the **control plane** owns jobs, YAML registry validation, policy, normalization, CLI/API and status UI; the **scanner/runtime plane** is represented by replaceable `ScannerAdapter` contracts; and the **preservation/integration plane** owns content-addressed quarantine and external manifest/RAB envelopes.

Business logic lives in application services shared by CLI and API. YAML is catalog truth. SQLite contains only mutable operational job state and may later migrate behind `JobService` without changing registry semantics.

M1.6 document parsing is bounded, read-only, in-process structural analysis.
Meaningful embedded files join the existing recursive object graph through
`EMBEDDED_FILE_OF`; package metadata parts and bookkeeping streams do not.

M1.4c partition discovery is a bounded range layer inside `ContainerAnalyzer`,
not a separate job system. A disk produces exact byte-bearing partition objects
through `PARTITION_OF`; verified filesystem files use `FILESYSTEM_ENTRY_OF`.
Every layer shares one recursive budget state and private cleanup tree.

M1.5 registers executable structure as another generic analyzer. Standalone and
recursive child jobs therefore use the same identity, result envelope, source
immutability, cleanup, and relationship provenance. Sections/segments/hunks
remain observations and do not become graph objects.

M1's `ScanService` selects only applicable file adapters. `SystemDetectorAdapter` is a separate contract for chkrootkit/rkhunter host inspection. Scanner execution remains replaceable and routes, templates, and CLI contain no detector-specific parsing.

Operational versions, probe status, definition state, and scan results are runtime data. Product identity, declared capabilities, installation provenance, and qualification intent remain Git-versioned YAML. Existing bootstrap-rescue tooling remains an external preservation producer, not an AVBox scanner or dependency.

M1.1 adds a generic protocol boundary: streamed intake and authentication in the API plane, versioned YAML analysis profiles, the existing persisted `ScanJob`, a bounded local worker queue, and semantic result mapping. It does not duplicate the job state machine or move profile/catalog truth into SQLite.

M1.2 activates generic analyzers on that same job. Exact identity and bounded
filename metadata are deterministic in-process analyzers; file identification
is an isolated external analyzer. Their typed `AnalyzerResult` values coexist
with scanner results without requiring or manufacturing a security verdict.

M1.3 adds bounded strings, whole-object byte statistics, isolated bounded
ExifTool metadata, and optional ssdeep similarity fingerprints. These analyzers
remain outer-object-only and produce observations/assessments, never security
verdicts. Similarity fingerprints never replace SHA-256 identity or CAS keys.
# Structural validation layer

The `structural-validator` is a generic analyzer class distinct from antivirus
engines and container enumeration. It attaches format-aware integrity facts and
assessments to an existing SHA-256 object identity. Exact derived objects remain
the responsibility of container transforms; blocks, tables and descriptors do
not become child objects.
