# M1.4c partitioned and hard-disk image traversal

M1.4c adds MBR primary partitions and Amiga RDB hardfiles to the existing
recursive analyzer. It does not add a second disk pipeline. The chain is
`disk -> PARTITION_OF -> partition -> FILESYSTEM_ENTRY_OF -> file`; archives
found as files re-enter the same recursive dispatcher.

## Partition objects and identity

Discovery uses a `BoundedRangeReader(start, length, root_size)`. Construction,
seek, and every physical read enforce the root and partition bounds. AVBox then
materializes the range into its private per-job derived area only when both the
256 MiB per-partition and 512 MiB job-total partition limits, plus all ordinary
child/byte/deadline limits, permit it. The effective per-object bound is the
smaller of the partition and ordinary child limits. This hybrid design avoids
unbounded copies while letting the already-qualified filesystem analyzers read
an ordinary immutable file.

The materialized range is hashed by the normal artifact service, yielding exact
SHA-256, BLAKE3, SHA-1, MD5, and size over precisely the partition bytes. Its
identity never includes offset, name, index, or scratch path. Two equal ranges
therefore deduplicate by content while their separate `PARTITION_OF` edges and
metadata preserve provenance. Metadata includes parent/root SHA-256,
`partition.scheme`, `.index`, `.start_bytes`, `.length_bytes`, `.type`, and
`.name` when present.

There is no metadata-only filesystem CAS object. A verified partition is the
filesystem-bearing object; files are linked directly from it with
`FILESYSTEM_ENTRY_OF`. Partition-table type hints and parser-verified
filesystems remain separate evidence.

## Qualified parsers

The internal read-only MBR parser requires a 512-byte sector model and 55AA
signature, records active flag/type/LBA start/count, ignores CHS, validates all
ranges, reports obvious overlaps, and retains valid primary siblings when an
entry is invalid. EBR is deferred.

The internal RDB parser locates `RDSK` in the first 16 conventional blocks,
validates checksums and block size, and follows bounded `PART` pointers with a
32-partition server maximum and cycle detection. It records block location,
name, DosType, cylinders, surfaces, blocks/track, byte range, and boot priority.
Geometry is used only after conservative range validation. `FSHD`/`LSEG`
filesystem-handler material is neither loaded nor executed; traversal always
uses AVBox's own OFS/FFS reader. GPT and flat HDF are deferred.

All parsing is userspace file I/O. No mount, mount syscall, loop device,
udisks, FUSE, guestmount, device mapper, boot, emulation, repair, recovery,
undelete, carving, slack, or unallocated-space scan exists in this path.

## Completeness and budgets

Partition, filesystem, and archive boundaries share the same `ExtractionUsage`,
recursion depth, child count, extracted-byte count, deadline, and cleanup tree.
A bad sibling adds a precise `PARTIAL_ERROR` while safe sibling objects remain.
Limit exhaustion produces `PARTIAL_LIMIT`. Structural corruption and bootable
flags never manufacture a security verdict. `recursive-default@1` remains
version 1 because partition traversal is additive within its existing recursive
container-discovery contract.

