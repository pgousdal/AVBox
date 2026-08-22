# M1.6 Document Static Analysis

AVBox M1.6 adds bounded, read-only structural identification for PDF, OLE/CFB,
OOXML, RTF and ODF packages.  The implementation is in-process Python using
the standard library (`zipfile`, `xml.etree.ElementTree`, `zlib`, and bounded
byte parsing). XML input is rejected before parsing when it contains a DTD or
entity declaration, and parsed trees have explicit byte, depth, element, and
attribute limits. No office suite, renderer, browser, or execution engine is
installed or invoked by document analysis.

Parsers emit Protocol v1 observations and non-verdict assessments.  URLs and
relationships are retained as untrusted metadata and are never fetched.
Macros, JavaScript, ODF scripts and embedded objects are never executed.
Meaningful embedded payloads are extracted only within the existing recursive
budgets and are submitted to normal child analysis.

Limits cover input bytes, package components, XML depth/elements, RTF nesting,
relationship counts, child bytes and recursion.  Malformed input produces
partial/error state while preserving identity and successful observations.

The built-in parser reports implementation version `1`. Protocol v1 exposes a
per-family `document_analysis.formats` state matrix, independently of profile
availability and implementation presence. `document-default@1` performs only
static structural analysis; `recursive-default@1` additionally admits
meaningful embedded payloads to the existing bounded child pipeline.

PDF observations cover version, indirect objects, streams, pages, xref/trailer
structures, metadata/XMP, names, embedded files, actions, forms, signatures,
encryption, and update terminators. CFB observations include sector geometry,
directory hierarchy, streams/storages, summary streams, VBA structures, macro
module/source presence and harmless auto-entry-point names. OOXML and ODF are
recognized from package content rather than filename or generic ZIP identity.
RTF analysis is a bounded structural scan; it does not render or decode
embedded objects.

`SIGNATURE_PRESENT` observations report structure only; AVBox does not claim
signature validity. `ENCRYPTED_DOCUMENT` retains outer evidence and produces
`PARTIAL_UNSUPPORTED`; no password is attempted. Active content, external
references, macro names, and embedded objects remain observations or
assessments. Only security analyzers create findings and security verdicts.
