# M1.4b bounded retro disk-image enumeration

M1.4b adds read-only FAT and Amiga ADF filesystem readers to the existing
`ContainerAnalyzer`. A filesystem file is materialized under the analyzer's
generated `child-NNNNNNNN` name, hashed, analyzed by the existing requested
analyzers, and linked by `FILESYSTEM_ENTRY_OF`. The untrusted logical path is
metadata only. Nested archives re-enter the same `_process_object` call and
therefore share one depth, child, byte, ratio, path, and deadline budget.

The versioned `recursive-default@1` profile is retained. Disk enumeration is an
additive content handler within its documented recursive object-discovery
contract; Protocol v1 and the analyzer list do not change. No host or scratch
path is added to Protocol output.

## Safety model

The readers use Python byte access only. They never call `mount`, `mount(2)`,
`losetup`, udisks, guestmount, FUSE, an emulator, or a block device. Recognition
is content-based: FAT requires a coherent BPB, boot signature, computed data
layout, and in-image sector extent; ADF requires exactly 901120 bytes, `DOS\0`
or `DOS\1`, and a checksummed type-2 root block at block 880. Extensions are not
used. Block/cluster bounds, cycles, counted strings, checksums, file sizes, and
entry types are validated. Corruption becomes `PARTIAL_ERROR` with
`CORRUPT_FILESYSTEM`; it never becomes a malware verdict.

FAT supports short names and bounded VFAT long-name decoding. ADF supports the
classic 512-byte OFS (`DOS\0`) and FFS (`DOS\1`) layouts, directory hash chains,
and file-header data pointers needed by standard 880 KiB floppies. International,
directory-cache, and long-name DOS variants are recognized as outside the
qualified set. ADF HDF/RDB and partition traversal are explicitly absent.

Nested LHA extraction continues to use Debian `lhasa` under the established
bubblewrap boundary: argv-only execution, read-only root/source, controlled
writable scratch, no network namespace, private `/tmp`, timeout, output/byte
bounds, unprivileged service account, and cleanup. The in-process disk readers
have no network code or external process path.

## Observations and protocol

Every disk child metadata record includes the exact disk-image format,
filesystem type, label when present, filesystem/image byte size, allocation
size, logical filesystem path, entry type, and byte size. ADF also records the
exact DOS type. Directory entries do not create byte identities; their context
is retained in file logical paths. Identical bytes share a SHA-256 identity but
retain separate relationships and member indexes.

`GET /api/v1/rab/capabilities` reports individual FAT12, FAT16, FAT32, ADF/OFS,
ADF/FFS, Atari ST, MSA, Apple DOS, ProDOS, and HFS states. It does not advertise
an umbrella retro-disk capability.

## Tool selection survey

| Candidate | Version/provenance/license | Behavior and decision |
|---|---|---|
| AVBox bounded FAT reader | repository source, project license | Read-only FAT12/16/32 enumeration; selected to avoid writable CLI and output parsing. |
| Debian mtools | 4.0.48-1 in Debian 13, GNU project/GPL | Mature userspace FAT tool with writes; useful survey/fixture option, not required at runtime. |
| Debian dosfstools | 4.2-1.1 in Debian 13, GPL | `mkfs.fat`/`fsck.fat`; fixture validation only, not runtime. |
| amitools/xdftool | pinned upstream 0.8.0, GitHub/PyPI, GPL-2.0 | Reputable OFS/FFS create/list/extract tool; independently validates qualification ADFs. Its broad writable HDF/RDB surface is unnecessary at runtime. |
| AVBox bounded ADF reader | repository source, project license | Small read-only DOS0/DOS1 880 KiB parser selected for runtime. |
| libarchive/7-Zip | Debian packages | Do not provide the required independently truthful OFS/FFS model. |
| Atari/Apple/HFS specialist tools | surveyed formats lack a smallest equally defensible qualified path in this milestone | Deferred rather than expanding into a forensic suite. |

The Amiga block implementation follows the Amiga ROM Kernel Reference Manual
filesystem structures and was cross-checked against independently generated
amitools images. Runtime dependencies are unchanged.

## Scope and limitations

Atari ST plain FAT may happen to satisfy the strict FAT reader, but no Atari ST
fixture was qualified and the capability remains `DEFERRED`. MSA needs bounded
decode-to-ST semantics and is deferred. Apple DOS 3.3 and ProDOS need separate
allocation/catalog semantics and are deferred. Classic HFS is deferred; in
particular, claiming it without distinct data/resource-fork objects would lose
essential semantics. HFS+, APFS, MBR, GPT, RDB, HDF, physical media, recovery,
repair, deleted files, slack, and carving are unsupported in M1.4b.
