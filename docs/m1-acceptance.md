# M1 acceptance

Automated acceptance requires tests, Ruff, strict mypy, package build, registry validation, CLI doctor, Ansible syntax validation, systemd unit verification, and two provisioning runs on Debian 13. Real qualification uses only harmless positive/negative files and runs system detectors only on the dedicated qualification target.

Each detector is reported independently as NOT_INSTALLED, INSTALLED, PROBED, QUALIFIED, DEGRADED, FAILED, DISABLED, or explicitly deferred. Adapter presence alone is not qualification. The qualification record must include package/upstream version, definitions/rules, update outcome, isolation evidence, output, and approximate elapsed time.

M1 accepts YARA-X, LOKI, or Maldet as deferred when no trusted reproducible Debian 13 installation path is available. It does not accept a false QUALIFIED state, silent scanner update, scanner error represented as CLEAN, source mutation, real malware, historical binaries, Windows workers, or a pushed commit.
