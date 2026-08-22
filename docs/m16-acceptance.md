# M1.6 acceptance

M1.6 passed on 2026-08-22 on the dedicated Debian 13.6 qualification VM. PDF,
OLE/CFB, harmless VBA, OOXML DOCX/XLSX/PPTX/DOCM, RTF, and ODT were genuinely
qualified through authenticated Protocol v1. ODF qualification is limited to
ODT; ODS and ODP are `IMPLEMENTED_NOT_QUALIFIED`.

Meaningful PDF, CFB, and OOXML payloads became exact `EMBEDDED_FILE_OF` child
objects under the existing global recursion budget. ISO→PDF→ZIP→text,
ZIP→OOXML→child, HDF→RDB→FFS→PDF, OOXML→PE32, and DOCM→CFB/VBA chains passed.
A harmless marker inside an OOXML child produced a child-attributed YARA
finding and aggregate `SUSPICIOUS` verdict while the root document's structural
assessments remained non-verdict evidence.

Malformed, encrypted, and limit cases retained identity and returned
`PARTIAL_ERROR`, `PARTIAL_UNSUPPORTED`, and `PARTIAL_LIMIT` as appropriate.
External relationships produced no connection to a controlled listener.
No macro, PDF JavaScript, submitted content, viewer, browser, renderer, or
office application executed. Source bytes were unchanged and all staging,
scratch, extraction, mount, loop, FUSE, and device-mapper cleanup gates passed.

The complete local and deployed regression suite passed 119 tests. Ruff,
strict mypy, compilation, both package builds, registry, doctor, Ansible
syntax, systemd verification, live API health, Protocol capability truth, and
two final Ansible runs passed. The last run reported `changed=0 failed=0`.

**M1.6 ACCEPTANCE: PASS.**
