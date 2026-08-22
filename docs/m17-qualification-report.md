# M1.7 qualification report

## Platform and provenance

Qualification date: 2026-08-23. Target: libvirt domain
`avbox-m1-qualification` (guest hostname `timemachine`), Debian 13 (trixie),
kernel `6.12.101+deb13-amd64`, x86-64, 2 vCPU, 4 GiB RAM, default libvirt NAT at
`192.168.122.212`, autostart disabled. The API remained bound only to
`127.0.0.1:8080`; the service was active and enabled.

Deployment used the existing `.state/m1-inventory.ini` and its explicitly named,
mode-0600 qualification key. The previous SSH failure was caused by not selecting
that project key; no credential, `authorized_keys`, password or root-login change
was required. Runtime validation uses Python standard-library parsers and existing
AVBox bounded range readers. Fixture construction and Debian pytest are
qualification-only tools; no M1.7 runtime dependency was added.

## Deterministic evidence

The full 128-test suite, including `tests/test_m17_structural_validation.py`,
constructs harmless ADF OFS/FFS,
FAT12/16/32, RDB/HDF, ISO9660 and LHA `-lh0-` objects locally and mutates targeted
bytes for checksum, copy, pointer, extent, CRC and truncation failures. Fixtures
are transient and are not shipped as copyrighted media. Tests assert exact source
SHA-256, immutability, structural state and a null security verdict.

The complete 128-test suite passed both locally and against the deployed source.
Authenticated `preservation-validation@1` jobs qualified clean and damaged OFS,
FFS, FAT12, FAT16, FAT32, RDB/HDF, ISO9660 and LHA `-lh0-` objects. Every Protocol
result retained the exact root SHA-256, exposed a structured `StructuralState`,
kept the security verdict null, and left the submitted fixture hash unchanged.
The deployed suite additionally exercises ADF bitmap/pointer/cycle/truncation,
FAT loop/cross-link/invalid cluster/truncation, RDB PART checksum/pointer/cycle/
bounds and valid-sibling retention, malformed/truncated ISO, and malformed/
truncated LHA.

The existing recursive regression proves HDF -> RDB -> FFS -> LHA -> child with
separate derived-object identities, ancestry and shared global budgets. RDB
validation reports aggregate table damage; a valid PART remains materializable
when a later PART is invalid. No claim of a separate per-PART `StructuralState`
field is made.

## Capability matrix

| Format/variant | Status | Depth |
| --- | --- | --- |
| ADF OFS DOS\0 | QUALIFIED | checksums, bitmap references, chains |
| ADF FFS DOS\1 | QUALIFIED | checksums, bitmap references, chains |
| FAT12/16/32 | QUALIFIED | BPB, copies, chains, directories, orphans |
| RDB/HDF | QUALIFIED | checksums, pointers, geometry, partitions |
| ISO9660 base | QUALIFIED | descriptors, records, extents |
| LHA `-lh0-` | QUALIFIED | header, length, CRC, truncation |
| DMS | DEFERRED | no qualified bounded decoder |
| Atari ST/MSA | DEFERRED | semantics/parser qualification required |
| Apple DOS/ProDOS | DEFERRED | bounded filesystem validators required |
| classic HFS | DEFERRED | fork and B-tree semantics incomplete |

The DMS survey found Debian main's `xdms` 1.3.2-7 package and source. It was not
installed or integrated: a safe DMS -> ADF path still needs adversarial decoder
qualification, bounded output/checksum handling, sandboxing and shared recursive
budget accounting. DMS therefore remains `DEFERRED`; Atari ST, MSA, Apple DOS,
ProDOS and HFS also remain `DEFERRED` for the reasons in the design document.

Before and after live jobs, `losetup -l`, FUSE `findmnt`, and `dmsetup ls` showed
no resources. AVBox staging, scratch and upload directories were empty. No mount,
loop device, FUSE, emulator, contained-code execution, repair, source write or
validator network operation exists in the implementation. Temporary qualification
fixtures were removed.
