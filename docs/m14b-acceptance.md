# M1.4b acceptance

M1.4b is accepted only from the evidence in
`docs/m14b-qualification-report.md`. Qualified support is FAT12, FAT16, FAT32,
Amiga ADF/OFS (`DOS\0`), and Amiga ADF/FFS (`DOS\1`). Atari ST/MSA, Apple DOS,
ProDOS, and classic HFS are deliberately `DEFERRED`; HDF/RDB and partitioned
hard disks remain outside this milestone.

The implementation is userspace-only and immutable. It does not mount, attach a
loop device, use FUSE, boot, execute submitted content, access preservation
storage, or start Windows/historical workers. Filesystem facts have no security
verdict mapping. Protocol v1 remains compatible and capabilities state each
filesystem variant independently.

The final local quality run, both package builds, registry/doctor checks,
Ansible syntax, two-run convergence, systemd verification, deployed Protocol v1
fixture jobs, cleanup/no-network evidence, and representative M1–M1.4a
regressions passed. The final Ansible pass was `changed=0 failed=0` and the
service remained active, healthy, and loopback-only.

M1.4b ACCEPTANCE: PASS
