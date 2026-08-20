# M1.1 acceptance

Acceptance requires protocol/model tests, authentication and authorization tests, streaming/hash/size/path tests, idempotency conflict handling, bounded queue behavior, restart reconciliation, safe result mapping, M1 regressions, Ruff, strict mypy, package builds, Ansible syntax, two Debian 13 provisioning passes, systemd validation, and harmless end-to-end clean/EICAR/YARA jobs.

Reference resolution, RAB correlation, recursive analysis, raw-output retrieval, and all broad M1.2 static analyzers remain explicitly unavailable. No Windows or historical worker is part of M1.1.

## Debian 13 qualification evidence

Qualification was performed on the dedicated `avbox-m1-qualification` Debian
13.6 VM, with the API remaining on `127.0.0.1:8080`.

- CLEAN: job `0f9253e1-766c-4cbf-aa05-709ad28d6767`, ClamAV and YARA clean,
  transient upload removed.
- EICAR: job `b4360e3a-cf2f-4fd5-bf37-8f464cd17ca2`, ClamAV
  `Eicar-Signature`, aggregate `MALICIOUS`, immutable quarantine admission.
- harmless YARA marker: job `0d052665-0962-4625-b0f8-69ccbc66141e`, exact
  ruleset SHA-256 `acb514df523f7660de73bde1f29d2c11a6ff48e0f4967ee5f38d978f802e07eb`,
  aggregate `SUSPICIOUS`.
- Idempotency returned the original clean job; conflicting reuse returned
  `IDEMPOTENCY_CONFLICT`.
- Incorrect declared SHA-256 returned `OBJECT_HASH_MISMATCH` before admission.
- Missing and invalid credentials returned `AUTHENTICATION_REQUIRED` without
  disclosing credentials.
- With queue capacity one, the third rapid submission returned `QUEUE_FULL`.
- Job `ee69d51f-34ab-4c76-a7e8-d52bcdcd3a88` completed cleanly while an
  ordinary service restart drained the queue; simulated unclean interruption
  reconciliation is covered by automated tests.
- The final two Ansible runs reported `changed=3` (deploying the final source
  hardening and restarting the service) and then `changed=0`.

Qualification exposed and fixed three M1 runtime defects: missing `AF_NETLINK`
for bubblewrap under systemd, isolation-startup exit code 1 being mistaken for
a ClamAV detection, and qualified state being transiently downgraded during a
scan. It also established a 1536 MiB bounded scanner address-space limit for
current ClamAV data and `KillMode=mixed` for graceful queue draining. The
original false-positive qualification record was retained as audit evidence.
