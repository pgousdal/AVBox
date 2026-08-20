# AVBox

AVBox is a private, personal, LAN-only multi-engine antivirus and malware-analysis appliance for the owner's files and media. M1 adds a current-Linux detector runtime while retaining the M0 control, scanner/runtime, and preservation boundaries.

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

Useful commands include `avbox scanner status`, `avbox scanner probe [SCANNER]`, `avbox scanner update SCANNER`, `avbox scan FILE [--scanner SCANNER]`, `avbox system-scan [--scanner chkrootkit|rkhunter]`, and `avbox job show JOB_ID`. Updates are administrative operations and never occur implicitly during a scan.

Untrusted input must stay on local, permission-restricted, preferably `nodev,nosuid,noexec` storage. Never expose staging or quarantine through SMB/NFS. M1 is hard-limited to `READ_ONLY`; it scans a private read-only staging copy and verifies that the submitted original did not change.

See [architecture](docs/architecture.md), [security model](docs/security-model.md), and [M1 acceptance](docs/m1-acceptance.md).
