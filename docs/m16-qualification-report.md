# M1.6 qualification report

Qualification date: 2026-08-22. Target: `avbox-m1-qualification`, Debian 13.6
x86-64, kernel `6.12.101+deb13-amd64`, 2 vCPU, 4 GiB, autostart disabled,
libvirt default NAT. The API listened only on `127.0.0.1:8080`.

## Dependencies and isolation

The document parser has no third-party runtime parser dependency. It uses
Python 3.13.5 standard-library `zipfile`, `xml.etree.ElementTree`, `struct`,
`re`, and `zlib` in process. AVBox limits document input and total package
expansion to 64 MiB, package/PDF/CFB components to 10,000, XML depth to 64,
and RTF groups to 256; existing recursive byte, child, depth, ratio, and time
budgets apply to extracted payloads. The service has `MemoryMax=2G`,
`LimitCORE=0`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `PrivateTmp=true`,
and a single writable `/var/lib/avbox` scope. Document parsing uses no external
process. ClamAV, YARA, 7-Zip, and LHA child/container invocations remain
argv-only, timeout/memory/core bounded, and bubblewrap `--unshare-net`
isolated.

Debian `genisoimage 9:1.1.11-4`, `python3-pypdf 5.4.0-1`, and the existing
Python test fixture builders were qualification-only dependencies. Debian
`pytest 8.3.5-2` and
`ansible-core 2.19.4-0+deb13u1` were qualification/deployment tools, not AVBox
runtime dependencies. No Office suite, LibreOffice, PDF viewer, browser,
JavaScript/VBA runtime, Wine, renderer, COM component, or password tool was
installed or invoked.

## Format matrix

| Capability | Evidence | State |
|---|---|---|
| PDF | ordinary, metadata/XMP, URI/JavaScript/OpenAction/AA, embedded file, signature structure, encryption structure, truncated fixture | QUALIFIED |
| OLE/CFB | genuine CFB sector/FAT/directory fixture, stream hierarchy, SummaryInformation, embedded Package, malformed header | QUALIFIED |
| VBA | genuine harmless XlsxWriter example project plus deterministic `AutoOpen` fixture; modules/source enumerated and never executed | QUALIFIED |
| OOXML DOCX | content types, properties, external relationship and package-aware identity | QUALIFIED |
| OOXML XLSX | package-aware identity and relationships | QUALIFIED |
| OOXML PPTX | package-aware identity and relationships | QUALIFIED |
| OOXML macro enabled | DOCM plus `vbaProject.bin` child entering CFB/VBA analysis | QUALIFIED |
| RTF | ordinary/nested/control/Unicode/object/field/URL, malformed and depth-limit fixtures | QUALIFIED |
| ODF | standards-conforming ODT mimetype/manifest/metadata/external-link fixture | QUALIFIED (ODT only) |

Only the listed features are qualified. PDF signature structure is observed;
cryptographic validity is `NOT_SUPPORTED`. PDF encryption is recognized and
reported as `PARTIAL_UNSUPPORTED`; passwords are neither supplied nor guessed.
ODF variants other than ODT remain `IMPLEMENTED_NOT_QUALIFIED`.

## Recursive and security evidence

Authenticated Protocol v1 jobs demonstrated:

- ISO→PDF→embedded ZIP→text at depths 1/2/3 with
  `FILESYSTEM_ENTRY_OF`, `EMBEDDED_FILE_OF`, and `CONTAINS` relationships.
- ZIP→OOXML→marker child at depths 1/2. Only the child YARA result
  `AVBox_Harmless_Positive` was `SUSPICIOUS`; ClamAV was `CLEAN`; the aggregate
  verdict was attributed from the child.
- HDF→RDB→FFS→PDF with exact partition/filesystem ancestry. An independent
  harmless marker filesystem child caused the aggregate YARA verdict.
- OOXML→embedded PE32; the child received exact identity and M1.5 PE analysis.
- DOCM→`vbaProject.bin`→CFB/VBA analysis without executing VBA.

Genuine VBA qualification used XlsxWriter's official harmless example
`vbaProject.bin` (`SHA-256
0ced1464b3677e98f5e3a8c5d80135e18dc98dca39299f1a8cfd2a00999fbf9f`)
as a fixture-generation-only input. The resulting XLSM job
`cb58caf9-b187-4441-a981-8ad6d7f7ae8f` enumerated five modules, their names and
paths, and bounded decompressed source presence. A separate deterministic
compressed MS-OVBA fixture demonstrated the harmless `AutoOpen` name. Neither
fixture is stored in Git and no VBA executed.

The PDF embedded child job retained two exact child identities and sizes. All
children inherited parent SHA-256, depth, package/stream provenance, global
budget accounting, and ordinary analyzers. Structural XML parts and ordinary
PDF/CFB streams were not emitted as children.

## Adversarial, network, immutability, and cleanup evidence

DTD/external-entity declarations, malformed XML, excessive XML depth,
expanded package size, truncated PDF/CFB, malformed RTF, and RTF depth limits
are covered by automated tests. Deployed truncated documents retained root
identity and returned precise partial states. The final RTF limit job returned
`PARTIAL_LIMIT`; encrypted PDF returned `PARTIAL_UNSUPPORTED`; neither created
a malware verdict.

A genuine harmless password-protected PDF generated with Debian pypdf had
SHA-256 `f5968c5e73d72a0943e1fa8d0fbf2062411a60ef7b9b798adf1a35deb9caac26`.
Protocol job `b282be11-8d70-4a1b-b7e4-0fa6eebace4f` recognized encryption,
retained safe outer evidence, returned `PARTIAL_UNSUPPORTED`, attempted no
password, and produced no security verdict.

OOXML and ODT fixtures referenced a controlled listener at
`127.0.0.1:18081`. The listener timed out without accepting a connection.
Static inspection confirms the document module has no socket, HTTP,
subprocess, renderer, JavaScript, VBA, viewer, or shell path. Source hashes
recorded before submission matched Protocol object identities and post-run
hashes. Extracted payload hashes matched independently generated bytes.

After success, malformed, encrypted, and limit jobs, RAB upload staging,
parser scratch, and derived extraction trees were empty. No loop, FUSE,
submitted-object mount, or device-mapper mapping existed.

## Gates

The complete suite passed locally and deployed: 119 tests. Ruff, strict mypy
over 46 source files, Python compilation, sdist and wheel builds, registry
validation, doctor, Ansible syntax, `systemd-analyze verify`, live health, and
authenticated Protocol v1 passed. Final Ansible convergence results and the
committed HEAD are recorded in `m16-acceptance.md`.
