# AVBox

AVBox is a private, personal, LAN-only digital-object analysis appliance. M1.4c
adds bounded userspace MBR and Amiga RDB partition traversal to the existing
recursive object graph and authenticated asynchronous RAB Protocol v1 jobs.
M1.5 adds non-executing PE, ELF, DOS MZ, and Amiga HUNK structural analysis.

AVBox is not a public scanning service, SaaS product, malware execution sandbox, or archive authority. RAB is the intended long-term preservation authority. The existing `avbox-bootstrap` scripts and reports remain time-critical staging infrastructure, not registry truth.

## M1 quick start

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/avbox registry validate
.venv/bin/avbox doctor
.venv/bin/pytest
.venv/bin/uvicorn avbox.api.app:app --host 127.0.0.1 --port 8080
```

Useful commands include `avbox analyze FILE --profile identification-default@1`, `avbox scanner status`, `avbox scanner probe [SCANNER]`, `avbox scanner update SCANNER`, `avbox scan FILE [--scanner SCANNER]`, `avbox system-scan [--scanner chkrootkit|rkhunter]`, and `avbox job show JOB_ID`. The RAB client supports `rab submit`, `rab job`, and `rab results`. Updates are administrative operations and never occur implicitly during analysis.

Untrusted input must stay on local, permission-restricted, preferably `nodev,nosuid,noexec` storage. Never expose staging or quarantine through SMB/NFS. M1 is hard-limited to `READ_ONLY`; it scans a private read-only staging copy and verifies that the submitted original did not change.

See [architecture](docs/architecture.md), [security model](docs/security-model.md),
[M1.4 container recursion](docs/m14-container-recursion.md), and
[M1.4c partitioned images](docs/m14c-partitioned-images.md).
Executable parsing is documented in
[M1.5 executable static analysis](docs/m15-executable-static-analysis.md).

RAB integration is documented in [RAB Protocol v1](docs/rab-protocol-v1.md). Protocol credentials are external secrets; never commit them.
