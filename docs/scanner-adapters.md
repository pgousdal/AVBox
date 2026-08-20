# Scanner adapters

Every runtime implements `probe`, `capabilities`, `prepare`, `scan`, `normalize`, and `cleanup`. Application services do not know whether it uses a local CLI, daemon/socket, VM, emulator or API.

Capabilities cover file, directory, archive, disk-image, boot-sector, memory and system scans plus scan-only/repair/delete/quarantine actions. Dependency mode distinguishes local, cloud-assisted and cloud-required engines. Registry evidence independently records offline-definition and snapshot support.

M1 implements command adapters for ClamAV, YARA, YARA-X, LOKI, and Maldet. A distinct system-detector contract implements chkrootkit and rkhunter. `probe()` reports observed state independently of declarative registry claims. `update()` is separate from `scan()`.

ClamAV uses `clamscan` in M1: it avoids a privileged long-running socket, has simple per-job isolation, and gives exact process/output attribution. The contract permits a future clamd strategy without changing application semantics. YARA and YARA-X share the controlled rules as versioned input but remain separate implementations and results.

YARA-X, LOKI, and Maldet may remain runtime-deferred when Debian 13 lacks an acceptable package. An implemented adapter is not `QUALIFIED` until a real probe and harmless positive/negative procedure succeeds.
