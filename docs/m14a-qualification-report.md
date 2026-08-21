# M1.4a final Debian qualification report

Qualification date: 2026-08-21. The repository started clean on `main` at
`cb9367506c7a71ce22f7264e91e640d2362435e3`, with `0 behind / 0 ahead` of
`origin/main`. Nothing was pushed. The dedicated target was
`avbox-m1-qualification` (hostname `timemachine`), Debian 13.6 (trixie), kernel
`6.12.101+deb13-amd64`, x86-64, 2 vCPU, 4 GiB RAM, libvirt default NAT at
`192.168.122.212`, with autostart disabled. No other guest or preservation
data was used.

## Deployment and toolchain

The first current-HEAD Ansible run reported `ok=22 changed=3 skipped=0
failed=0`; its unchanged second run reported `ok=20 changed=0 skipped=1
failed=0`. After qualification fixes, the same final two-run gate was repeated
and the second run again had `changed=0 failed=0`.

Runtime packages were Debian packages: `lhasa 0.4.0-1+b2` (Lhasa v0.4.0),
`7zip 25.01+dfsg-1~deb13u2` (7-Zip 25.01), `bubblewrap
0.11.0-2+deb13u1` (0.11.0), `file 1:5.46-5` with `libmagic1`, ExifTool
13.25, ssdeep 2.14.1, ClamAV 1.4.3, and YARA 4.5.2. Debian `xorriso
1.5.6-1.2+b1` was installed only to generate the harmless ISO fixture; it is
not an AVBox runtime dependency.

On Debian 13 the exact source tree passed the full test suite, Ruff, strict
mypy (42 source files), Python compilation, registry validation, doctor, and
isolated builds of `avbox-0.4.0.tar.gz` and
`avbox-0.4.0-py3-none-any.whl`. Ansible syntax, `git diff --check`, and
`systemd-analyze verify` passed. The service was active from
`/opt/avbox/source`, bound only to `127.0.0.1:8080`.

## Runtime isolation

The deployed external-handler argv is wrapped by bubblewrap with
`--unshare-net --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp`; LHA adds
only a generated per-member scratch bind. A harmless diagnostic under that
exact profile ran Debian 7z successfully, could not modify its mode-0400
source or `/etc`, could write only the bound scratch, and could not connect to
`1.1.1.1:80`. It ran as `uid=999 gid=989`, saw only bubblewrap's minimal
synthetic devices, and had a zero core limit. The systemd unit retained
`NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
`PrivateDevices=yes`, an empty capability bounding set, `ReadWritePaths` only
for `/var/lib/avbox`, restricted address families, `MemoryMax=2G`,
`TasksMax=256`, and `LimitCORE=0`.

ISO traversal used only Debian `7z l -slt` and `7z e -so`. Before and after
the ISO jobs, `losetup -a` and ISO9660 mounts were empty. AVBox contains no
mount or loop invocation. Rock Ridge and Joliet were present in the generated
test image but are not advertised and were not independently qualified as
distinct naming views.

## Fixture and Protocol evidence

All fixture content was locally generated, deterministic, harmless, and never
executed. The ISO was made by Debian xorriso from a root file, nested files,
duplicate bytes, and a nested ZIP. The 7z and encrypted 7z were made by Debian
7-Zip. The level-0 LHA writer was a tiny local implementation of the level-0
header, CRC-16, and uncompressed `-lh0-` records; Debian lhasa independently
listed, CRC-checked, and extracted it before AVBox submission. No downloaded
archive corpus was used.

The ISO root SHA-256 was
`e8d72013704a0ad8419d486a85dd4e99bac7ffd29c4517e4948b7dd80b09fef3`.
Protocol v1 returned separate `FILESYSTEM_ENTRY_OF` edges for
`nested/copy.txt` and `nested/one.txt` to the same child SHA-256, plus
`nested.zip` and `root.txt`; the nested ZIP produced `inside.txt` at depth 2.
The ISO was not identified as tar. A signature-preserving truncated ISO
returned `PARTIAL_ERROR` with `CORRUPT_CONTAINER`, no child, no manufactured
security verdict, and no crash.

The real 7z returned five byte-bearing objects and five edges; directory
metadata was not emitted as files, duplicate members retained two edges to one
SHA-256, and a nested ZIP recursed to depth 2. Header-encrypted 7z, with no
password supplied, returned `PARTIAL_UNSUPPORTED` and `ENCRYPTED_CONTAINER`.

The real LHA root SHA-256 was
`14182476461f22e43d1064d49d4aaa5c23da2862618f392b08dc187534102e3d`.
It produced `hello.txt` and `inner.zip` as depth-1 `-lh0-` children and
`inside.txt` through ZIP at depth 2: three objects, three `CONTAINS` edges,
correct hashes, and no limit event. Thus only `-lh0-` is method-qualified;
`-lh5-` and other methods are not claimed. Nested paths and spaces passed.
The raw UTF-8 name fixture was not accepted by legacy lhasa name decoding and
is not qualified. Lhasa normalized `../escape` before listing; AVBox itself
rejected `/absolute`, and the exact sandbox exposed no host output path. A
truncated LHA retained its first safe child and precisely reported the failed
second member without crashing or inventing a malware verdict.

A deliberately low `max_total_children=2` run over real LHA -> ZIP materialized
only the two LHA children, observed the attempted third child, emitted
`TOTAL_CHILD_COUNT_LIMIT`, and removed derived and scratch data. This proves
one global budget spans handler boundaries. Existing depth, byte, expansion,
path, and deadline regression tests use the same shared usage and start time.

The controlled YARA marker inside `positive-lh0.lzh` was attributed to
`marker.txt` at depth 1 as `SUSPICIOUS`; the root direct scanner results
remained distinct and recursive aggregation/quarantine followed existing
policy. Clean ISO, 7z, and LHA roots had identical SHA-256 before and after.
Successful, corrupt, encrypted, and budget-limited jobs left staging and RAB
upload directories empty and no generated scratch trees.

## Final capability matrix

| Format | Recognition | Extraction | Recursion | Path/budget safety | Sandbox | Real fixture | Status |
|---|---|---|---|---|---|---|---|
| ZIP | yes | yes | yes | qualified | built-in | yes | QUALIFIED |
| tar | yes | yes | yes | qualified | built-in | yes | QUALIFIED |
| gzip | yes | yes | yes | qualified | built-in | yes | QUALIFIED |
| bzip2 | yes | yes | yes | qualified | built-in | yes | QUALIFIED |
| xz | yes | yes | yes | qualified | built-in | yes | QUALIFIED |
| LHA/LZH (`-lh0-`) | yes | yes | yes | qualified | bwrap | yes | QUALIFIED |
| ISO9660 | yes | yes | yes | qualified | bwrap, no mount | yes | QUALIFIED |
| 7z | yes | yes | yes | qualified | bwrap | yes | QUALIFIED |
| CAB | yes | no | no | recognition only | n/a | no | DEFERRED |
| ARJ | yes | no | no | recognition only | n/a | no | DEFERRED |
| Amiga LZX | no | no | no | n/a | n/a | no | DEFERRED |
| RAR | recognition only | no | no | n/a | n/a | no | DEFERRED |

No M1.4b, Windows worker, historical worker, proprietary extractor, real
malware, or preservation operation was used.
