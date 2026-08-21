# M1.4a qualification report

## Environment

The repository started at `27c8789`, on `main`, clean, with `0 behind / 1
ahead` relative to `origin/main`.  Local qualification used the project
`.venv` (Python 3.14.4) and the installed Debian-family tools:

| Package/tool | Version | Use | Status |
|---|---:|---|---|
| lhasa | 0.5.0 | LHA/LZH listing and extraction | qualified by interface; fixture generation unavailable |
| 7zip | 26.00 | 7z and ISO userspace listing/extraction | qualified with deterministic fixtures |
| xorriso | 1.5.6 | harmless ISO fixture generation only | test utility |

The full Python suite passes (`73 passed`). Ruff, compilation, and existing
regression tests pass. A Debian qualification VM, Ansible convergence,
systemd runtime checks, and network/mount observation were not available in
this sandbox; those remain deployment gates.

## Handler matrix

| Format | Recognized | Extracted | Recursive | Path/budget boundary | Real-qualified | Status |
|---|---:|---:|---:|---:|---:|---|
| ZIP | yes | yes | yes | yes | yes | QUALIFIED |
| tar | yes | yes | yes | yes | yes | QUALIFIED |
| gzip/bzip2/xz | yes | yes | yes | yes | yes | QUALIFIED |
| LHA/LZH | yes | yes | yes | yes | interface tested | QUALIFIED pending VM fixture |
| ISO9660 | yes | yes | yes | yes | yes | QUALIFIED |
| 7z | yes | yes | yes | yes | yes | QUALIFIED |
| CAB | yes | deferred | no | recognition only | no | DEFERRED |
| ARJ | yes | deferred | no | recognition only | no | DEFERRED |
| Amiga LZX | deferred | deferred | no | n/a | no | DEFERRED |
| RAR | recognized where identified | deferred | no | n/a | no | DEFERRED |

ISO traversal is performed by 7-Zip `l`/`e -so` in userspace. AVBox does not
invoke mount, loop devices, FUSE, or adjacent-volume lookup. External commands
are argv-only and, when bubblewrap is enabled, run with network unshared,
read-only root visibility, controlled writable scratch, and no shell.

Known deployment gates are intentionally not represented as qualification
claims. No M1.4b functionality was started.
