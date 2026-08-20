# Bootstrap preservation environment

The `avbox-bootstrap` VM and scripts under `bin/` and `host/` are a temporary preservation producer created before M0. Its separate store exports immutable bytes and provenance for later RAB ingest.

AVBox consumes generic verified external manifests. Bootstrap artifacts are not copied into AVBox's YAML registry, and AVBox never depends on the VM being online. See `reports/` for preservation status.
