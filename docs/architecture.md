# Architecture

AVBox has three boundaries: the **control plane** owns jobs, YAML registry validation, policy, normalization, CLI/API and status UI; the **scanner/runtime plane** is represented by replaceable `ScannerAdapter` contracts; and the **preservation/integration plane** owns content-addressed quarantine and external manifest/RAB envelopes.

Business logic lives in application services shared by CLI and API. YAML is catalog truth. SQLite contains only mutable operational job state and may later migrate behind `JobService` without changing registry semantics.

The suggested layout is followed. Existing bootstrap-rescue tooling remains in `bin/`, `host/`, `installer/`, and `reports/` as an external preservation producer, not an AVBox scanner.

