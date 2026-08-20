# Security model

M1 treats submissions and scanner parsers as untrusted. The hard default is `ScanPolicy.READ_ONLY`. Adapters reject remediation arguments, scan a mode-0400 copy, and compare source size/SHA-256 before and after execution. Filenames are labels; SHA-256 is identity. Raw output is stored mode 0400 outside SQLite and is never interpreted as HTML.

Production directories are owned by unprivileged `avbox` with mode 0700. Staging and quarantine should be separate `nodev,nosuid,noexec` mounts; the included script verifies this. They must not be shared over SMB/NFS.

Clean working bytes are deleted after scanning by later lifecycle orchestration. Malicious, suspicious and PUA bytes may enter immutable content-addressed quarantine. There is no automatic redistribution.

File scanners run through bubblewrap when available with a read-only host view, private temporary directory, new session, and an unshared network namespace. They receive a controlled environment, working directory, timeout, address-space limit, and zero core limit. The Debian 13 baseline allows 1536 MiB per scanner process because current ClamAV definitions can exceed a 1024 MiB address space; systemd still bounds the complete service. A direct bounded fallback is explicit in runtime evidence. System detectors intentionally need host visibility and are not exposed as ordinary file scanners.

The main service removes capabilities, enables `NoNewPrivileges`, protects system/home/kernel/control groups, uses private devices/tmp, sets task/memory/core limits, and grants writes only to `/var/lib/avbox`. Scanner updates run separately and may use network access; ordinary bubblewrap scans do not.

RAB upload authentication is independent of network locality. Tokens are externally stored and constant-time compared. Uploads are bounded and streamed to generated paths; caller filenames, URLs, URIs, and paths cannot select host resources. Authentication failures, forbidden scopes, hash mismatches, queue rejection, and job outcomes are audited without credentials or request headers.
