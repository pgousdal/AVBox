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

| Fixture | Bytes | SHA-256 | BLAKE3 |
|---|---:|---|---|
| FAT12 | 1474560 | `0681f5f0281597d0d8e23f229e60d9ebb4ee739c2f9b26d18f345bf324d1d5e8` | `4c13a93caacd584a7d24be4c5d91aa22918942b1b2506fb2186d41c388e64ea6` |
| FAT16 | 16777216 | `157c2b16e6b7b3e3aeb1bed4f85fc25587c4dcf6b85008bd0045811c9bfcb892` | `9466e7495356641ea1bfede87732e8c3038318df42b536a97f70b26f0230d00f` |
| FAT32 | 67108864 | `bfcb5c4298bbee3c5f36c010ea92b2612987f7b964fa8a2dadfa55b6ce5f9cf4` | `3249d2dd129a6cadd94874139a4f9dd6ae0c8a7697ab74e051f0a400f4117f2d` |
| ADF/OFS | 901120 | `36e6da1ba91d989db8824e59c3a9b385bb29a79535b394f990216e58942ee12d` | `df8035d2d2b41aabee84a08849fa98f48fcb8050c06ab56ff797066c4375e642` |
| ADF/FFS | 901120 | `0eae4f714da14b3f90aee1a682f2588e41c85cc422f77e6d66d9e9fa3f496357` | `c4d37236dc3cc030f453141f63b2571f7d14e9d24183dfd7a7902d9895ccba7d` |
| child-attribution ADF/OFS | 901120 | `462d6b7ae2e81e62336f4260f444a8d1ac22e5bb0f6154b0c8714b5d96124fc5` | `dcf3e84ede21f7a763b411d41e3b626d1d75c59485b412bcf0253e7ca63dba11` |

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

The deployed Protocol jobs completed with six materialized objects for every
FAT variant (five filesystem files plus ZIP child) and seven for each primary
ADF (six filesystem files plus LHA child). OFS/FFS duplicate entries both
resolved to SHA-256
`3f84cce967052e85c3cf2d671c2433dc4899226bb99a67d6bfe4aeb9e938b7cc`
while retaining distinct edges. The child-only OFS marker fixture deliberately
placed the marker across OFS data-block payload boundaries: root YARA was
`CLEAN`, child `avbox-m14b-attribution/YARA-MARKER` was `SUSPICIOUS`, and the
aggregate was `SUSPICIOUS`/quarantined. Before and after root hashes matched for
all five matrix images.

Damaged FAT12 and checksummed-root OFS jobs completed operationally with
`completeness=PARTIAL_ERROR`, `CORRUPT_FILESYSTEM`, retained root SHA-256, no
crash, and no transient tree. The corruption fact itself created no finding or
security mapping. A low-budget automated disk/archive test materialized exactly
the global limit and reported `TOTAL_CHILD_COUNT_LIMIT`/`PARTIAL_LIMIT`.

The external LHA path listed and extracted `lha-child.txt` as uid 999/gid 989
inside bubblewrap. A socket attempt to `1.1.1.1:80` in the identical
`--unshare-net` boundary failed with `ENETUNREACH`. Post-run `findmnt` showed no
FUSE filesystem, `losetup -l` was empty, derived staging and pending upload
searches were empty, and the service listened only on `127.0.0.1:8080`.

Runtime versions were Debian `bubblewrap 0.11.0-2+deb13u1`, `lhasa 0.4.0-1+b2`,
and `7zip 25.01+dfsg-1~deb13u2`; disk parsing added no runtime package. Debian
survey candidates `dosfstools 4.2-1.2` and `mtools 4.0.48-1` remained uninstalled.

The final source verification ran 82 pytest tests, Ruff, strict mypy over 43
source files, Python compilation, registry validation, doctor, Ansible syntax,
and `git diff --check`. Builds produced `avbox-0.4.0.tar.gz` and
`avbox-0.4.0-py3-none-any.whl`. The final Ansible pass was `changed=0 failed=0`.
`systemd-analyze verify` returned no diagnostics; `avbox` was active/enabled.
Representative real recursive jobs exercised the M1 security, M1.2 identity,
M1.3 static, and M1.4a LHA/ZIP paths without changing their semantics.

Final command and deployed-runtime results are recorded in the acceptance file.
