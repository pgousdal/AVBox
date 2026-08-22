# M1.4b Debian 13 qualification report

Qualification date: 2026-08-22. Target: `avbox-m1-qualification`, Debian 13.6
x86-64, 2 vCPU, 4 GiB, libvirt default NAT, autostart disabled. Deployment used
the repository Ansible role; fixture-only tools were not added to the service.

## Deterministic fixture provenance

FAT fixtures are constructed deterministically by the test fixture builder with
512-byte sectors, explicit BPBs/FATs/directories, duplicate content, a drawer,
and a ZIP containing `inside.txt`. `dosfstools fsck.fat` 4.2 independently
validated FAT12/16/32 layouts. ADF source files are harmless locally created
text, duplicate bytes, `DRAWER/CHILD`, an `-lh0-` archive, and the established
YARA marker. Pinned upstream `amitools 0.8.0` `xdftool format ... ofs|ffs` created
standard 901120-byte images; `xdftool -r list` independently reported DOS0/OFS
and DOS1/FFS. No copyrighted OS media or malware was used.

Fixture timestamps are metadata and not used for recognition. The report's
qualification command transcript records SHA-256, BLAKE3, sizes, before/after
hashes, API graphs, cleanup, and corruption cases.

## Qualification matrix

| Image/filesystem | Real fixture | Recognition / enumeration / extraction | Nested recursion | Safety/corruption/budget/immutability | Status |
|---|---|---|---|---|---|
| FAT12 | deterministic 1.44 MiB image | content BPB; correct paths and hashes | FAT→ZIP→text passed | path checks; partial corruption; global limits; unchanged | QUALIFIED |
| FAT16 | deterministic 16 MiB image | independently tested and extracted | ZIP chain passed | same bounded reader; unchanged | QUALIFIED |
| FAT32 | deterministic 64 MiB image | independently tested and extracted | ZIP chain passed | same bounded reader; unchanged | QUALIFIED |
| ADF/OFS | amitools DOS0 880 KiB | root/drawer/files and hashes correct | ADF→LHA `-lh0-`→text passed | checksum/bounds/corruption; unchanged | QUALIFIED |
| ADF/FFS | amitools DOS1 880 KiB | independently recognized and extracted | LHA chain passed | checksum/bounds/corruption; unchanged | QUALIFIED |
| Atari ST | none | FAT similarities investigated; Atari-specific boot/layout not claimed | not run | no evidence inflation | DEFERRED |
| Atari MSA | none | compressed wrapper needs bounded decoder | not run | no casual FAT treatment | DEFERRED |
| Apple DOS | none | separate catalog/allocation parser required | not run | no suffix inference | DEFERRED |
| ProDOS | none | separate volume/directory parser required | not run | no suffix inference | DEFERRED |
| HFS | none | userspace tooling exists but fork-safe object semantics not established | not run | resource fork loss would be incomplete | DEFERRED |

## Safety and regression evidence

All real parsing is userspace-only. VM inspection found no loop attachment and
no mount/FUSE entry created by qualification. In-process FAT/ADF reading has no
network path. The only external mixed-chain process, `lhasa`, retained
bubblewrap `--unshare-net`, read-only root/source, private temporary storage,
unprivileged UID/GID, bounded output/time/resources, and cleanup.

Tail/structure damage retained root identity and safe earlier observations where
available, set a precise partial state, and did not add `MALICIOUS`,
`SUSPICIOUS`, or `PUA`. Duplicate file bytes produced one SHA-256 value and two
filesystem-entry edges. Low global-child limits crossed disk/archive boundaries
without resetting. The harmless YARA result belonged to `YARA-MARKER`; direct
ADF security stayed distinct and the aggregate became `SUSPICIOUS` under the
unchanged quarantine policy.

Final command and deployed-runtime results are recorded in the acceptance file.
