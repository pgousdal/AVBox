# M1.4a container extensions

M1.4a extends the existing generic object graph and recursive-default@1
extractor.  It does not add a second job model, mounting, loop devices, or
RAB writeback.

| Format | Recognition | Extraction | Handler |
|---|---|---|---|
| ZIP, tar, gzip, bzip2, xz | qualified | qualified | Python userspace |
| LHA/LZH | qualified | qualified | Debian `lhasa` 0.5.0 |
| ISO9660 | qualified | qualified | Debian `7z` 26.00 userspace |
| 7z | qualified | qualified | Debian `7z` 26.00 |
| CAB, ARJ | recognized | deferred | Debian `7z` 26.00 (not real-qualified) |
| Amiga LZX | deferred | deferred | no accepted Debian implementation |
| RAR | recognized where identified | deferred | licensing/supply-chain policy |

LHA member names are retained as untrusted metadata and checked against the
same traversal, length, and depth limits as other containers.  Extraction is
read-only and streamed into generated scratch paths; archive-selected paths
are never used as host output paths.  Legacy encoding uncertainty does not
prevent byte extraction.  Comments, checksums, timestamps, and protection
bits are observations only and never become host permissions or identity.

ISO traversal uses 7-Zip's userspace ISO reader (`l`/`e -so`); AVBox never
invokes mount, loop, FUSE, or kernel filesystem traversal.  Regular files are
byte-bearing children with `FILESYSTEM_ENTRY_OF` relationships.  Directory
entries and special files are metadata/structure only.  The visible ISO name
is provenance metadata; child SHA-256 remains the byte identity.  Rock Ridge
and Joliet view selection is delegated to the reader and remains explicitly
recorded when available.

Encrypted and missing-volume inputs are not cracked or fetched.  Unsupported
methods and malformed structures produce partial completeness and preserve
any safely enumerated children.  All formats consume one global extraction
budget across nested transitions.
