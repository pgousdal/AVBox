# Architecture

AVBox has three boundaries: the **control plane** owns jobs, YAML registry validation, policy, normalization, CLI/API and status UI; the **scanner/runtime plane** is represented by replaceable `ScannerAdapter` contracts; and the **preservation/integration plane** owns content-addressed quarantine and external manifest/RAB envelopes.

Business logic lives in application services shared by CLI and API. YAML is catalog truth. SQLite contains only mutable operational job state and may later migrate behind `JobService` without changing registry semantics.

M1's `ScanService` selects only applicable file adapters. `SystemDetectorAdapter` is a separate contract for chkrootkit/rkhunter host inspection. Scanner execution remains replaceable and routes, templates, and CLI contain no detector-specific parsing.

Operational versions, probe status, definition state, and scan results are runtime data. Product identity, declared capabilities, installation provenance, and qualification intent remain Git-versioned YAML. Existing bootstrap-rescue tooling remains an external preservation producer, not an AVBox scanner or dependency.

M1.1 adds a generic protocol boundary: streamed intake and authentication in the API plane, versioned YAML analysis profiles, the existing persisted `ScanJob`, a bounded local worker queue, and semantic result mapping. It does not duplicate the job state machine or move profile/catalog truth into SQLite.
