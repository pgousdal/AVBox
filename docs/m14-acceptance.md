# M1.4 Acceptance

M1.4 is accepted when the Debian 13 qualification target demonstrates
userspace ZIP, tar, gzip, bzip2, and xz discovery; independent child hashes;
machine-readable graph relationships; nested recursion; and enforced depth,
child-count, byte, expansion, name, path, and time budgets. Tests cover
duplicate names/content, unsafe paths, symlinks/hardlinks, corrupt input,
partial results, cleanup, and recursive security attribution using harmless
fixtures only.

The milestone deliberately excludes 7z when a trusted qualification is not
available, ISO mounting/traversal, LHA/LZX and retro disk formats, recursive
RAB preservation writes, deep executable/document parsing, and dynamic
analysis. These are future RAB/AVBox work, not reasons to weaken M1.4
sandboxing.

Protocol v1 reports root and child objects, relationships, budget usage and
analysis completeness. `CLEAN` is never inferred from an extraction limit or
parser failure.
