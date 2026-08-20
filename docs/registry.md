# Registry

`config/registry/registry.yaml` is Git-versioned truth. Typed collections model platforms, products, scanner releases, detector releases, definition sets, runtime profiles and worker profiles. Validation rejects duplicate IDs and broken product/platform/runtime/worker references.

Product version, scanner-engine version, definition version and definition date are distinct nullable fields. Unknown values remain null. Capabilities and cloud/offline properties require evidence; placeholders explicitly say `not-installed` or `qualification-incomplete`.

Historical modes are `PERIOD_CORRECT`, `FINAL_HISTORICAL`, and `MAXIMUM_RETRO`. A mode is a qualification target, not proof that a placeholder works.

