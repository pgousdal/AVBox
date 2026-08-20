# RAB integration

The implemented machine boundary is RAB Protocol v1; see `rab-protocol-v1.md`.

RAB requests a versioned analysis profile and supplies bytes with an expected
SHA-256; AVBox returns a result envelope keyed to request, job, and artifact.
`identification-default@1` supplies exact fixity, safe filename interpretation,
and libmagic evidence for optional RAB metadata enrichment and preservation
triage. AVBox performs no metadata writeback. Quarantined AVBox artifacts may
later be offered for ingest, after which RAB becomes preservation authority.

`ExternalPreservationManifest` is the common boundary for bootstrap exports and future RAB catalogs. It carries four hashes, size, source URLs, independent product/engine/definition fields, compatibility, relationships, provenance, failures and rights. AVBox does not copy an external catalog into its registry or require bootstrap online.

Bootstrap exports remain external holdings. `examples/external-preservation-manifest.json` demonstrates the format without importing them.
