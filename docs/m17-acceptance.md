# M1.7 acceptance

M1.7 is accepted. The implementation provides the separate structural state
model, Protocol v1 representation, `preservation-validation@1`, exact per-variant
capabilities, read-only validators and deterministic tests for all mandatory
formats.

Qualification on `avbox-m1-qualification` demonstrated full deployed regression,
authenticated Protocol v1 clean/damaged format jobs, immutable source hashes,
null security verdicts for structural damage, loopback-only health, systemd
hardening, cleanup and absence of mount/loop/FUSE/device mappings. Optional DMS,
Atari, Apple II and HFS targets remain explicitly deferred.

Final local and deployment command results, Ansible recaps, build artifact names,
commit and divergence are recorded in the final handoff.

Status: **PASS**.
