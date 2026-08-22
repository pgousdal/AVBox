# M1.7 retro/media structural validation

M1.7 adds the built-in `structural-validator` and the
`preservation-validation@1` profile. Validation is an observation layer over an
existing object identity. It is not a malware scanner and never repairs input.

The Protocol v1 analyzer result contains `structural_validation` with validator,
format, variant, state, observations, structural findings, assessments,
completeness, confidence, exact source SHA-256, validator version, duration and
limit/error state. The result envelope also collects root validation results in
its `structural_validation` array. Security `verdict` remains independently
nullable.

## Qualified depth

- ADF DOS\0 OFS and DOS\1 FFS: exact size and geometry, DOS type, boot checksum,
  root type/checksum, bitmap references/checksums, bounded directory hash chains,
  file data references, OFS data-block structure/checksums, loops, reused blocks,
  range errors and truncated chains. International and directory-cache DOS types
  are recognized but not qualified. Bitmap free-space accounting and orphan-block
  proof are not claimed.
- FAT12/16/32: BPB/layout/bounds/type, FAT-copy equality, bounded directory and
  cluster traversal, invalid/reserved references, loops, cross-links, file size
  versus chain length and orphan allocated clusters. No recovery or carving.
- Amiga RDB/HDF: RDSK discovery, RDB and PART checksum handling, block size,
  linked PART bounds/cycles, partition geometry/bounds/overlap and DosType
  metadata. FSHD/LSEG content is never loaded and is explicitly DATA ONLY.
- ISO9660 base: descriptor sequence/PVD/terminator, block and volume bounds,
  root/directory record bounds, extent bounds and bounded directory recursion.
  Path-table equivalence, full Rock Ridge and full Joliet validation are deferred.
- LHA level-0 `-lh0-`: header checksum/shape, method, packed length, member CRC and
  truncation. Other methods are not qualified.

Validation is bounded by `max_structural_validation_bytes` (256 MiB default) and
`max_structural_validation_nodes` (100,000 default). RDB and ISO use range reads;
ADF and FAT are admitted to memory only below the byte limit. No count from media
can bypass the node bound.

## Optional-format survey

DMS is deferred. Debian 13 does provide the maintained `xdms` 1.3.2-7 package,
but integrating that external C decompressor safely requires a separate
adversarial-decoder, sandbox, checksum and shared derived-byte-budget
qualification before its ADF output may enter recursive analysis. Installing it
without those controls would not establish preservation validation. Atari ST/MSA,
Apple II DOS/ProDOS and classic HFS are likewise deferred. Plain ST images must
not be claimed merely because their layout resembles PC FAT. HFS remains deferred
until catalog/extents trees and both data and resource forks can be validated
without semantic loss. Amiga LZX is deferred for lack of a trustworthy qualified
parser.

No dependency or supply-chain exception was introduced for these targets.
