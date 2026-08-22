# M1.4c acceptance record

Starting state was clean `main` at
`2a9106c65f52125141dfac8ff4e170b516412559`, exactly synchronized with
`origin/main` (0 behind, 0 ahead). Nothing is pushed by this milestone.

## Final verification

Target `avbox-m1-qualification` was Debian 13.6 x86-64, 2 vCPU/4 GiB. The final
full Ansible convergence was `ok=22 changed=3 failed=0`; its immediate second
pass was `ok=20 changed=0 failed=0 skipped=1`.

Deterministic fixtures and final identities:

| Fixture | Bytes | SHA-256 | BLAKE3 |
|---|---:|---|---|
| MBR + FAT12 | 3145728 | `696a16e1046aaa63e2a442ced80f43df9cce83301377e9adf941fbe1624be64b` | `281837cfedd6720af4bc280f18575687031fc746313857e86ac25153dab3627e` |
| FAT12 partition | 1474560 | `e8e6c7f8f982657278fb26603316266af4333919ac459f60d2d24a25d5fcebc9` | `5d1032725ae6f7535758810b7c2cb08892345707e598611a789997d61abc70c3` |
| RDB/HDF + FFS | 1802240 | `95dcb3f6108d250716209b4858e7c2dffa054798fdd83a542b072a3e270742b9` | `e3c91e8925c32e0e534902a23ecba230b15dee3cd4462154f3dae539ffa5f743` |
| FFS partition | 901120 | `a2c285bbc850d39b77f2a2018b7127bc80137f08f98d9c16dc5703bd32340c5c` | `1d3cdf607c2079d6f12416a50b72390d7748682749e4f2e1f2ef6538d396bb63` |

Protocol job `b162ee0a-2545-4555-b839-74d8f5d1f0be` completed CLEAN and
COMPLETE. It reported MBR partition 0 at byte 1048576, length 1474560, type
0x06, active, exact four-hash identity, one `PARTITION_OF`, five
`FILESYSTEM_ENTRY_OF`, and a ZIP `CONTAINS` edge to depth 3. Usage was seven
children, 1474759 total extracted bytes, exactly 1474560 partition bytes, and
no limit event.

Protocol job `d2d9a0f8-ffe9-442b-b2b3-a3dcffaf512a` completed operationally
QUARANTINED, SUSPICIOUS, and COMPLETE. Root direct and partition direct verdicts
were CLEAN. The exact `YARA-MARKER` filesystem child alone was SUSPICIOUS with
`AVBox_Harmless_Positive`; the aggregate was SUSPICIOUS under unchanged policy.
RDB metadata was block 0/512 bytes, `DH0`, DOS\1, low/high cylinder 1, one
surface, 1760 blocks/track, boot priority 0, start 901120, length 901120. The
LHA child reached depth 3 with SHA-256
`034887952f66f70a10f8c1bd40d970e5df71b1576d0d58a379da4673db4a4ed9`.
Usage was eight children, 901769 extracted bytes, exactly 901120 partition
bytes, and no limit or error.

Deployed corrupt jobs retained root identity, direct/aggregate CLEAN, no graph
edges, and `PARTIAL_ERROR`: invalid MBR signature reported
`CORRUPT_PARTITION_TABLE`; invalid RDB checksum did likewise. Automated tests
also cover out-of-range entries/geometry, valid sibling retention, pointer
cycles/bounds, overlaps, duplicate partitions and children, exact range
hashing, range seek/read bounds, and cross-layer global limits.

Before/after deployed SHA-256 values matched. Post-run `losetup -l` and
FUSE `findmnt` were empty; `lsblk` showed only VM `vda` and `sr0`; `dmsetup ls`
reported no devices. No derived directories or pending uploads remained.
`systemd-analyze verify` emitted no diagnostics; `avbox` was active/enabled and
only `127.0.0.1:8080` listened. Ordinary external child tools retain
bubblewrap `--unshare-net`; partition parsing itself has no network/process
path. RDB handler/loadseg code is never parsed as executable logic.

Final local verification: 88 pytest tests passed; Ruff passed; strict mypy
passed over 44 source files; compilation and `git diff --check` passed;
registry validation and doctor passed; Ansible syntax passed. Builds produced
`avbox-0.4.0.tar.gz` and `avbox-0.4.0-py3-none-any.whl`. The full suite covers
the existing M1 through M1.4b paths, including flat FAT/ADF, ISO, ZIP, LHA, 7z,
generic static analysis, ClamAV and YARA contracts.

EBR, GPT, flat HDF, recovery, repair, undelete, carving, unallocated space,
booting, mounts, loop/FUSE/device mappings, and later milestones remain absent.
