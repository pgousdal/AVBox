# AVBox

AVBox is a private, personal, LAN-only multi-engine antivirus and malware-analysis appliance for the owner's files and media. M0 provides the control-plane foundation, declarative registry, safety models, CLI, API/status page, preservation boundary, and Debian provisioning. It installs and runs no scanner.

AVBox is not a public scanning service, SaaS product, malware execution sandbox, or archive authority. RAB is the intended long-term preservation authority. The existing `avbox-bootstrap` scripts and reports remain time-critical staging infrastructure, not registry truth.

## M0 quick start

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/avbox registry validate
.venv/bin/avbox doctor
.venv/bin/pytest
.venv/bin/uvicorn avbox.api.app:app --host 127.0.0.1 --port 8080
```

Useful commands: `avbox doctor`, `avbox registry validate`, `avbox registry platforms`, `avbox registry scanners`, `avbox job list`, and `avbox artifact hash FILE`.

Untrusted input must stay on local, permission-restricted, preferably `nodev,nosuid,noexec` storage. Never expose staging or quarantine through SMB/NFS. M0 is hard-limited to `READ_ONLY`; it neither disinfects nor modifies an original.

See [architecture](docs/architecture.md), [security model](docs/security-model.md), and [M0 acceptance](docs/m0-acceptance.md).

