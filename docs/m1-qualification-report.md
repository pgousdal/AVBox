# M1 Debian 13 qualification report

Qualification date: 2026-08-20 UTC. Target: `avbox-m1-qualification`, Debian 13.6 x86-64, 2 vCPU, 4 GiB, existing libvirt `default` NAT. It was cloned solely from the shut-down Debian 13 base; no historical artifacts or other guests were accessed.

## Provisioning

The initial clean-target run exposed missing `python3-packaging`; a later idempotence pass exposed disagreement with systemd's default state-directory mode and repeated local package installation. The role now installs the dependency, specifies `StateDirectoryMode=0700`, and gates package installation on copied-source changes. The final unchanged pass completed with `ok=17 changed=0 skipped=1 failed=0`.

Installed from Debian 13 repositories:

| Detector/support | Debian version | Result |
|---|---:|---|
| ClamAV / freshclam | 1.4.3+dfsg-1 | QUALIFIED |
| YARA | 4.5.2-1 | QUALIFIED |
| chkrootkit | 0.58b-5+b7 | QUALIFIED system detector |
| rkhunter | 1.4.6-13 | QUALIFIED system detector |
| bubblewrap | 0.11.0-2+deb13u1 | real file scans isolated |
| YARA-X | unavailable in Debian 13 | DEFERRED |
| Python LOKI | Debian package name collision; upstream project deprecated/inactive | DEFERRED |
| Maldet | unavailable in Debian 13 | DEFERRED |

The Debian `loki` package is not the Nextron IOC scanner and was deliberately not installed. No third-party repository or unpinned installer was used.

## File-detector qualification

ClamAV reported engine/package 1.4.3 and daily definitions 28098 (build 2026-08-20 06:24 UTC, 355,612 signatures), main 63 (3,287,027 signatures), and bytecode 339 (80 signatures). An explicit `freshclam` operation returned success and confirmed all three databases unchanged/up to date. It warned that upstream recommends engine 1.4.6; Debian's package remains the selected trusted installation source.

The correct 68-byte harmless EICAR fixture had SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`. ClamAV returned `Eicar-Test-Signature`, normalized MALICIOUS, in 6.96 s. A harmless negative returned CLEAN. Source SHA-256, 68-byte size, owner, and mode 0400 were unchanged after scanning. Result runtime profile was `linux-bwrap-read-only-no-network`.

YARA used ruleset `avbox-m1.yar`, SHA-256 `acb514df523f7660de73bde1f29d2c11a6ff48e0f4967ee5f38d978f802e07eb`. The harmless positive matched `AVBox_Harmless_Positive` and normalized SUSPICIOUS; the negative returned CLEAN. Native execution took approximately 0.015 s. Both results recorded YARA 4.5.2 and the exact ruleset hash.

End-to-end wall time, including Python startup/hashing/storage, was about 7.76 s for a ClamAV negative and 0.28 s for a YARA negative. A ClamAV probe took about 0.28 s. Scanner address space is configured to 1024 MiB; the target lacked `/usr/bin/time`, so peak RSS was not collected rather than installing another package solely for benchmarking.

## System-detector qualification

chkrootkit completed in 12.56 s and reported Debian-owned Ruby `.document` files, the controlled missing HOME, and dhcpcd as a packet sniffer. rkhunter completed in 113.86 s and warned about newly installed `clamav`/`avbox` accounts, an unset SSH `PermitRootLogin`, and `/etc/.updated`. These are retained verbatim as raw output and normalized SUSPICIOUS/rootkit-warning, not MALICIOUS.

## Safety and lifecycle evidence

Real file results report bubblewrap isolation with an unshared network namespace. The runner also applies 300 s timeout, 1024 MiB address-space limit, zero core limit, controlled environment, read-only root view and mode-0400 staging. Remediation arguments are rejected in tests. Updates use a separate CLI operation and ordinary scans do not update.

Clean job staging was empty after execution. The harmless positive objects entered mode-0400 SHA-256 CAS paths; the external fixtures remained unchanged. Raw output is mode 0400, content-hashed, referenced from SQLite, and never rendered by the UI. API upload remains deliberately deferred.

## Qualification conclusion

ClamAV, YARA, chkrootkit and rkhunter satisfy real Debian 13 M1 qualification. YARA-X, LOKI and Maldet have complete adapters but remain honestly NOT_INSTALLED/deferred for trusted packaging or lifecycle reasons. No real malware, historical AV binary, Windows worker, historical VM or preservation-store object was used.
