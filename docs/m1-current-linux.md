# M1 current Linux worker

## Detector inventory and provenance

| ID | Class | Installation source | Update operation | File job |
|---|---|---|---|---|
| clamav | antivirus engine | Debian 13 `clamav` | explicit `freshclam` | yes |
| yara | rule engine | Debian 13 `yara` | versioned rules deployment | yes |
| yara-x | rule engine | official pinned upstream required | versioned rules deployment | yes when qualified |
| loki | IOC detector | official pinned upstream required (Debian package named `loki` is unrelated) | explicit corpus update | yes when qualified |
| maldet | malware detector | official R-fx release required | explicit signature update | yes when qualified |
| chkrootkit | system detector | Debian 13 `chkrootkit` | package upgrade | no |
| rkhunter | system detector | Debian 13 `rkhunter` | explicit property/database update | no |

YARA and YARA-X are related rule engines, not independent antivirus engines. chkrootkit and rkhunter inspect the dedicated appliance and are not file scanners. Optional upstream tools are deferred instead of using unpinned scripts or arbitrary repositories. Python LOKI is deprecated/in inactive maintenance upstream, which strengthens the case for a separately reviewed LOKI-RS adapter rather than an improvised installation.

## Definitions and rules

Scanning never updates. ClamAV records available `main`, `daily`, and `bytecode` database filenames, mtimes, and SHA-256 values. The controlled harmless YARA ruleset records its filename and SHA-256. LOKI/Maldet corpus detail remains UNKNOWN if the installed tool cannot expose an exact state. Administrative updates record command output and must be invoked explicitly.

The controlled ruleset contains only deterministic AVBox markers. EICAR qualification is generated at test time from its published harmless test specification and is never a malware corpus.

## Isolation and lifecycle

Ordinary files are copied to per-job mode-0400 staging. bubblewrap provides a read-only host tree, no network namespace, private `/tmp`, and a new session. The command runner applies a timeout, address-space ceiling, no core dumps, controlled environment, and forbidden-remediation argument check. The original is rehashed after scanning. Clean staging is deleted; actionable verdicts copy into immutable quarantine CAS.

System tools require appliance visibility and therefore use the bounded runner without bubblewrap. They should run only on a dedicated AVBox target, with warnings interpreted as ambiguous findings. rkhunter baseline/database update is never part of scan.

## Known limitations

M1 supports ordinary files only. It does not unpack archives, mount images, upload through the API, repair files, use cloud scanning, or schedule definition updates. API submission is deferred; CLI submission avoids expanding the attack surface while result/status endpoints are available. Mount options `nodev,nosuid,noexec` remain an administrator filesystem responsibility and are checked/documented rather than silently assumed.
