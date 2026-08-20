# M1.2 generic identity and file type

M1.2 answers “what is this object?” with evidence, not filename trust. It adds
three object analyzers to the existing job and RAB Protocol v1 boundary:

- `identity` (`identity_analyzer`) emits SHA-256, BLAKE3, SHA-1, MD5, and size
  already verified during streaming ingestion.
- `basic-metadata` (`metadata_analyzer`) treats the submitted filename as
  untrusted text and emits its original value, basename interpretation, length,
  suffixes, normalized extension, compound extension, and declared media type.
- `file-type` (`file_type_analyzer`) runs Debian `file`/libmagic in the bounded
  bubblewrap profile with a read-only host view and no network. It independently
  records description, MIME type, and MIME encoding.

`identification-default@1` contains exactly these analyzers.
`security-default@1` remains exactly ClamAV plus YARA.

## Evidence and confidence

Stable observation kinds are:

```text
identity.sha256             identity.blake3
identity.sha1               identity.md5
object.size                 object.declared_media_type
filename.original           filename.basename
filename.length             filename.extensions
filename.extension          filename.compound_extension
file.magic.description      file.mime.type
file.mime.encoding
```

Stable M1.2 assessment kinds are:

```text
FILE_TYPE
EXTENSION_TYPE_MISMATCH
EXTENSION_MIME_MISMATCH
DECLARED_MEDIA_TYPE_MISMATCH
MULTIPLE_EXTENSION
PLATFORM_HINT
ARCHITECTURE_HINT
BINARY_TEXT_CLASS
```

Observations are analyzer facts. Assessments are conservative interpretations
with `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN` confidence. Exact ingestion identity
uses the separate value `exact`. Empty, text, and image MIME values and explicit
container/executable markers produce high confidence; unrecognized results
remain unknown. Platform and architecture hints require direct libmagic text.

Known compound suffixes are deliberately bounded to `tar.gz`, `tar.bz2`,
`tar.xz`, and `tar.zst`. Other multiple suffixes produce `MULTIPLE_EXTENSION`,
which is context—not a security detection. Extension and declared-MIME
disagreement are likewise assessments and never create a malware verdict.

## Safety and partial results

No analyzer executes, mounts, opens through a native application, or unpacks
the object. `file` receives only a generated staging path and has no network.
Its elapsed time and address space are bounded. Raw output is stored as an
opaque, hashed text reference and is never rendered as HTML.

If libmagic is missing, times out, fails, or cannot enter isolation, its result
records an explicit error. Exact identity and metadata remain available, the
job may complete with partial results, and no security verdict is manufactured.

RAB can use these facts for identification, metadata enrichment, extension
normalization, format discovery, and preservation triage. AVBox does not write
metadata into RAB or decide which observations RAB accepts. Recursive analysis,
archive enumeration, deep executable/document/media parsing, ExifTool, strings,
entropy, and fuzzy hashing remain unavailable.
