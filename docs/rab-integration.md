# RAB integration

The implemented machine boundary is RAB Protocol v1; see `rab-protocol-v1.md`.

RAB may request a scan by SHA-256 and scanner set; AVBox returns a result envelope keyed to request, job and artifact. Quarantined AVBox artifacts may later be offered for ingest, after which RAB becomes preservation authority.

`ExternalPreservationManifest` is the common boundary for bootstrap exports and future RAB catalogs. It carries four hashes, size, source URLs, independent product/engine/definition fields, compatibility, relationships, provenance, failures and rights. AVBox does not copy an external catalog into its registry or require bootstrap online.

The bootstrap export's 23 verified artifacts remain external holdings. `examples/external-preservation-manifest.json` demonstrates the format without importing them.
