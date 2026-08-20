# M1.2 acceptance

Acceptance requires generic analyzer and Protocol v1 tests, real Debian 13
`file`/libmagic qualification using harmless empty/text/PNG/ZIP and filename
mismatch fixtures, unchanged `security-default@1`, complete M1/M1.1 regression
checks, package/lint/type/systemd checks, and a zero-change second Ansible run.

## Debian 13 qualification evidence

Qualification ran on the dedicated `avbox-m1-qualification` Debian 13.6 x86-64
VM on 2026-08-20. The trusted packages were `file`, `libmagic-mgc`, and
`libmagic1t64`, all Debian version `1:5.46-5`; `file --version` reported 5.46
and `/etc/magic:/usr/share/misc/magic`. The first final convergence changed
three deployment tasks. The immediately repeated Ansible run was `ok=20`,
`changed=0`, `failed=0`.

All fixtures were harmless, deterministically generated, submitted over the
authenticated RAB Protocol v1 HTTP boundary, and analyzed with
`identification-default@1`:

| Fixture | Job | Verified result |
|---|---|---|
| empty (`empty.bin`) | `af6f14cf-9b23-4816-ae43-11976aec9bc5` | size 0; `inode/x-empty`; SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| ASCII text (`plain.txt`) | `e30ea274-2e00-4423-87b7-48afead00f12` | `ASCII text`; `text/plain`; `us-ascii`; SHA-256 `34a6c27476bac24a0ed350382f66a255e386d69441c99951ddb362fd6c6bfe5b` |
| 1x1 PNG (`pixel.png`) | `19484512-e72d-4596-8650-3aa1246eb4bb` | `image/png`; SHA-256 `431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460` |
| ZIP outer object (`outer.zip`) | `7109053c-b9e9-457c-bf45-c0ddb00564ee` | `application/zip`; SHA-256 `22b2ce191ebf55ef5b9911185d237861431a6deb4ad172db992739e17387c53a`; no child enumeration/extraction |
| ZIP named `.zip.exe` | `e7bedd17-cdd2-435b-ab41-f133ead0e721` | `MULTIPLE_EXTENSION`, extension/type and extension/MIME mismatch assessments |
| PNG named `report.pdf.exe` | `94f9713d-f16d-4810-85de-c270cd7ddbaa` | `MULTIPLE_EXTENSION`, extension/type and extension/MIME mismatch assessments |
| text declared `image/jpeg` | `aa11fdf4-0d91-4700-808a-3b869d5ee8a3` | `DECLARED_MEDIA_TYPE_MISMATCH` |

Every job completed without analyzer errors and with `verdict: null`. The upload
staging directory contained zero files afterward. A real ClamAV plus YARA
regression scan (`ceefa20b-0e94-432d-ae6b-516b21cbec33`) completed CLEAN with
both detectors CLEAN. The service remained loopback-only and retained
`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateDevices=yes`, and
`NoNewPrivileges=yes`; `systemd-analyze verify` reported no errors.
