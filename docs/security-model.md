# Security model

M0 treats future submissions and scanner artifacts as untrusted. The hard default is `ScanPolicy.READ_ONLY`; `PolicyService` rejects `REPAIR_COPY` during M0. Filenames are labels, while SHA-256 is identity. Raw outputs are referenced, never discarded, and submitted contents are never logged.

Production directories are owned by unprivileged `avbox` with mode 0700. Staging and quarantine should be separate `nodev,nosuid,noexec` mounts; the included script verifies this. They must not be shared over SMB/NFS.

Clean working bytes are deleted after scanning by later lifecycle orchestration. Malicious, suspicious and PUA bytes may enter immutable content-addressed quarantine. There is no automatic redistribution.

The service removes capabilities, enables `NoNewPrivileges`, protects system/home/kernel/control groups, uses private devices/tmp, and grants writes only to `/var/lib/avbox`.

