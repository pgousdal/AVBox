# M1.5 executable static analysis

M1.5 adds the `executable` generic analyzer. It reads immutable object bytes,
performs bounded structural parsing, and returns stable observations and
conservative assessments. It never loads, executes, emulates, disassembles,
decompiles, repairs, relocates into executable memory, validates trust, or
invokes a packer.

## Parser selection

Debian 13.6 offered `python3-pefile 2024.8.26-2.1`,
`python3-pyelftools 0.32-1`, and `python3-macholib 1.16.3+ds-2`. None was
installed, and AVBox's isolated venv does not inherit system packages. A small
in-process parser was selected to avoid opaque frameworks, subprocess output
translation, and new runtime dependencies. Debian `file 5.46-5` and GNU
binutils `2.44-3` independently validate fixtures; they are not parser logic.

The parser accepts at most 64 MiB per object and caps headers, sections, imports,
symbols, names, Mach-O architectures, and HUNK records. Every offset/range is
checked before access. Attacker-controlled counts never drive unbounded
allocation. Recognized truncation returns `native_status=corrupt`, precise
errors, retained root identity, and job `PARTIAL_ERROR`. Non-executables return
`not_applicable`; oversized inputs return `unsupported_limit`.

## Formats and semantics

- PE32/PE32+: DOS/PE signatures, COFF machine/characteristics/timestamp,
  optional-header format, entry RVA, image base, subsystem, DLL flags,
  sections, directories, imports, exports, certificate/resource/debug/TLS/
  relocation/CLR presence through directory metadata, and overlay extent.
- ELF32/ELF64: class, byte order, ABI, type, machine, entry, program and section
  headers, interpreter, dynamic dependencies, SONAME, RPATH/RUNPATH, symbol
  count, and GNU build ID. `LIKELY_STRIPPED` is a medium-confidence assessment
  only when an executable/shared object lacks `.symtab`.
- DOS MZ: header, relocation table, register entry state, and new-header
  offset. NE/LE/LX are distinguished and minimally represented but remain
  implemented-not-qualified.
- Amiga HUNK: HUNK_HEADER and declared memory flags/sizes; CODE, DATA, BSS,
  relocation groups, symbols, DEBUG presence, and END records. Unknown record
  numbers are reported in the precise error and never guessed.
- Mach-O: thin/FAT header and bounded load/slice tables are implemented but not
  qualified because no trustworthy real fixture matrix was established.

Sections, segments, and hunks are structural metadata, not new CAS objects.
`executable-default@1` adds explicit standalone analysis. The existing
`recursive-default@1` additively requests executable structure for every root
and derived child, preserving Protocol v1, SHA-256 ancestry, relationships,
global recursive limits, and security attribution.

Executable observations and assessments never populate security findings or a
verdict. ClamAV/YARA remain independent security analyzers; only their results
can make a recursive aggregate MALICIOUS/SUSPICIOUS/PUA.

