# M1.4a acceptance record

The implementation is qualified locally with harmless fixtures through the
existing M1.4 tests plus harmless 7z and ISO fixtures through the same
recursive object graph.  Debian package
provenance is used for `lhasa` 0.5.0 and `7zip` 26.00.  Amiga LZX remains
DEFERRED: it is distinct from CAB's LZX compression and no accepted,
auditable Debian reader is installed.  RAR remains deferred for licensing and
supply-chain reasons. CAB and ARJ are recognized by 7z but remain deferred
until dedicated real fixtures and runtime qualification are available.

The acceptance boundary remains userspace-only extraction, bounded streamed
materialization, exact SHA-256 child identity, path safety, cleanup, and
recursive child attribution.  No preservation write, execution, mounting, or
filesystem validation is part of M1.4a.
