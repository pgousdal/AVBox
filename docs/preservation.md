# Preservation

Quarantine uses `sha256/<prefix>/<full-sha256>` addressing and immutable mode after admission. Only malicious, suspicious or PUA verdicts may be admitted. Clean bytes are not archive holdings.

Future repair copies an immutable original to a working area. `RepairRecord` requires distinct source, working-copy and repaired hashes, scanner/version/definition identity, action, raw output and timestamp. Repair against the original fails validation.

Possession/provenance are separate from rights. `redistribution_rights` defaults to `unknown`; public URLs, abandonware claims and physical ownership do not change it.

