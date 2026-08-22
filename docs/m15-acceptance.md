# M1.5 acceptance record

Starting state: clean `main` at
`519157c3a3fb6f3b4b63747a54f530250df129f5`, divergence 0 behind / 1 ahead
from `origin/main`. Nothing is pushed.

## Final verification

M1.5 passed its deployed qualification on `avbox-m1-qualification` (Debian 13.6
x86-64, 2 vCPU, 4 GiB). The final deployment converged at `ok=22 changed=3
failed=0`; the immediate second run was `ok=20 changed=0 failed=0 skipped=1`.

- PE32/I386 and PE32+/AMD64 were independently recognized by Debian `file` and
  GNU `objdump`, then returned structured Protocol v1 results with correct
  formats, architectures, entry points, and sections.
- ELF32/I386 and ELF64/X86_64 were independently recognized by `file`; GNU
  `readelf` also validated the real Debian ELF64 fixture's interpreter,
  sections, build ID, and `libc.so.6` dependency.
- DOS MZ and Amiga HUNK/M68K completed real deployed analysis. Debian `file`
  independently identified the HUNK fixture, whose result includes HEADER,
  CODE, DATA, BSS, RELOC32, SYMBOL, and END records.
- NE, LE, LX, and Mach-O have bounded recognition/parsing tests but no trusted
  real qualification matrix, and are truthfully `IMPLEMENTED_NOT_QUALIFIED`.
- Truncated PE, ELF, MZ, HUNK, and Mach-O fixtures retain SHA-256 identity,
  return precise corrupt/partial results, and never create a security verdict.
- ZIP→PE and HDF→RDB→FFS→HUNK/LHA→HUNK completed with exact child identity and
  ancestry. A separate harmless YARA-positive filesystem child alone made the
  latter aggregate SUSPICIOUS; both HUNK objects remained CLEAN.
- Before/after fixture hashes matched. There were no job trees, pending RAB
  uploads, or per-job scratch directories after success or failure.
- No executable was run. The parser has no execution/subprocess path. Existing
  detector subprocesses retain bubblewrap network isolation, controlled argv,
  resource limits, timeouts, and zero-core policy.
- Final inspection found no loop devices, FUSE mounts, or device-mapper
  mappings. The service was active/enabled, verified without systemd warnings,
  and bound only to `127.0.0.1:8080`.

The final local verification passed: 109 pytest tests, Ruff, strict mypy over 45
source files, Python compilation, registry validation, doctor, Ansible syntax,
systemd verification, source-distribution build, wheel build, and
`git diff --check`. Package artifacts were `avbox-0.4.0.tar.gz` and
`avbox-0.4.0-py3-none-any.whl`.

M1.5 ACCEPTANCE: PASS
