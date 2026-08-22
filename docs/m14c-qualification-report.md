# M1.4c qualification report

Qualification date: 2026-08-22. Production parser dependencies are unchanged:
the MBR/RDB/range implementation is Python userspace code. Deterministic test
builders create harmless MBR disks containing qualified FAT images and RDB/HDF
images containing qualified OFS/FFS bytes. They contain local text, duplicate
content, nested ZIP or LHA `-lh0-`, and the established harmless YARA marker;
no OS image or malware is used.

| Path | Automated evidence | Status |
|---|---|---|
| MBR primary -> FAT -> ZIP -> text | exact bounds/hash/edges, nested traversal, immutable root | QUALIFIED |
| two MBR primary partitions | independent edges; equal bytes deduplicate without provenance loss | QUALIFIED |
| RDB/HDF -> FFS -> LHA -> text | checksum, geometry, metadata, edges, recursion, immutable root; deployed Protocol v1 | QUALIFIED |
| RDB checksum/pointer/cycle damage | bounded failure or precise partial result; no hang | QUALIFIED |
| corrupt MBR / invalid sibling | root and safe sibling retained; no security verdict | QUALIFIED |
| EBR | explicitly deferred | DEFERRED |
| GPT | deferred rather than adding incomplete CRC/backup semantics | DEFERRED |
| flat HDF | not qualified | DEFERRED |

Exact final test/build/deployment counts, fixture hashes, platform facts,
service health, and no-mount/no-block inspection are recorded after the last
source change in `m14c-acceptance.md`. Synthetic tests are not described as
deployed evidence.
