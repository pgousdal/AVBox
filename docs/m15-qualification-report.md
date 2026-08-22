# M1.5 qualification report

Qualification date: 2026-08-22. Target: `avbox-m1-qualification`, Debian 13.6
x86-64, 2 vCPU, 4 GiB, autostart disabled, default libvirt NAT. AVBox remained
loopback-only. Exact deployed jobs and final command results are recorded in
`m15-acceptance.md`.

Deterministic harmless fixtures were generated locally and kept outside Git.
`file 5.46-5` independently recognized PE32/I386, PE32+/x86-64, ELF32/I386,
ELF64/x86-64, DOS MZ, and AmigaOS loadseg/HUNK. GNU `objdump 2.44-3`
independently confirmed both PE architectures, entry points, and `.text`
sections; `readelf 2.44-3` confirmed the ELF64 headers, interpreter, sections,
build ID, and `libc.so.6`. The HUNK fixture contains HEADER, CODE, DATA, BSS,
RELOC32, SYMBOL, and END records. No malware, copyrighted OS image, or fixture
binary is committed.

| Family | Evidence | Status |
|---|---|---|
| PE32 I386 | AVBox plus file/objdump, deployed Protocol v1 | QUALIFIED |
| PE32+ AMD64 | AVBox plus file/objdump, deployed Protocol v1 | QUALIFIED |
| ELF32 I386 | AVBox plus file, deterministic header fixture | QUALIFIED |
| ELF64 X86_64 | real Debian `/bin/true`, file/readelf, deployed Protocol v1 | QUALIFIED |
| DOS MZ | AVBox plus file, deployed Protocol v1 | QUALIFIED |
| Amiga HUNK M68K | AVBox plus file, deployed recursive qualification | QUALIFIED |
| NE/LE/LX | bounded identification tests only | IMPLEMENTED_NOT_QUALIFIED |
| Mach-O thin/FAT | bounded parser and corruption tests only | IMPLEMENTED_NOT_QUALIFIED |

Truncated fixtures for every parser family, huge counts, bad ranges, unknown
machines, unknown HUNK records, and parser byte limits are automated. Recursive
qualification covers ZIP→PE and HDF→RDB→FFS→HUNK. Existing archive, disk,
partition, identity, static, Protocol, ClamAV, and YARA tests remain active.

Fixture SHA-256 values were rechecked after qualification:

- PE32: `e38d2dcca328297fdc991de5817b39e1e9bf3c450b34b87ea7d39fe8926a812f`
- PE32+: `d841ce4add051dd5f3121fe2276e27516478a38148078a8f0c5a5c9bc3aa0fbb`
- ELF32: `abfb4323bd3e78e2459a6dd96c003f9b7933737730b8e87b6ad90cb7eb429a47`
- ELF64: `7d659da07aad1d5d1ed79e9f2822d24d2dea47ceec4c7e2e71718a177dc20b4b`
- DOS MZ: `a840ffd5afca4b5f18beda376cbd1d7bdc5d36c4afc826757619308db6746afa`
- Amiga HUNK: `ebfe41c4f1a17187f5063965e82a20d88a1d327e51178a3fba713ae3dc3a2d20`
- RDB/HDF recursive carrier: `f8863de8bf69afcaa2186eb75dbe4b6533507189ab51ae8519be93218bd1750e`

Standalone Protocol jobs for PE32, PE32+, ELF32, ELF64, MZ, and HUNK were
`f76b1f6f-aa55-47d5-9ef5-554c706c07fe`,
`a7bb5280-fe83-47ef-b06d-29c56454664e`,
`092843bf-fa3d-4166-b1d8-0c96f09e5082`,
`1c7cd064-52f0-45db-b9eb-3ef20318369c`,
`a22a860b-6ef8-4b9b-89b2-d89a738cdc0b`, and
`0da8bbdd-5bc4-4956-b34c-9d58438d3904`. All completed with null verdicts.

ZIP→PE job `ed56b64e-74e6-412d-98a2-f922e3a3980e` retained the exact PE child
identity and `CONTAINS` edge. RDB/HDF job
`fd65b5fd-d249-4ad6-9ce9-adbe100e62c6` traversed RDB→FFS and found the same
HUNK both directly and inside LHA. The HUNK objects remained CLEAN; an unrelated
harmless YARA marker child was SUSPICIOUS and alone caused the aggregate result.
This demonstrates that executable structure does not manufacture a verdict.

Final host inspection found no loop devices, FUSE mounts, or device-mapper
mappings. `systemd-analyze verify` emitted no diagnostics; the service was
active/enabled and listened only on `127.0.0.1:8080`. Job, pending-upload, and
per-job scratch searches were empty. The fixture hashes above were unchanged.
The last two deployments reported `changed=3 failed=0` and then
`changed=0 failed=0`.
