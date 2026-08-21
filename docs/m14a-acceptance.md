# M1.4a acceptance record

M1.4a passed its final Debian 13.6 qualification on 2026-08-21. Real deployed
Protocol v1 jobs qualified ISO9660, 7z, and LHA/LZH `-lh0-` under bubblewrap,
including cross-format recursion, exact child identity and graph edges,
no-network/no-mount evidence, global budgets, unsafe paths, corruption,
encryption, harmless child-positive attribution, root immutability, and
success/failure cleanup. The final Ansible run was idempotent and the complete
post-change verification/build gate passed.

LHA qualification is deliberately method-specific: `-lh0-` is QUALIFIED;
other LHA methods and raw legacy-name encodings are not independently
qualified. Rock Ridge and Joliet are not separately advertised or qualified.
CAB, ARJ, Amiga LZX, and RAR remain DEFERRED. See
`docs/m14a-qualification-report.md` for exact versions and evidence.
