# M1.3 generic static characteristics

M1.3 examines exactly one submitted outer object. It does not execute,
mount, unpack, enumerate, extract, or recurse into containers. It extends the
M1.2 Protocol v1 result envelope with four generic analyzers:

* `strings` uses an internal bounded extractor for ASCII, UTF-8, UTF-16LE and
  UTF-16BE. Defaults are a 4-character minimum, 4096-character per-string
  maximum, 2000 returned strings, 200,000 returned characters, and a 16 MiB
  source scan limit. `strings.truncated` and `STRING_OUTPUT_TRUNCATED` make
  every bound visible. Strings are inert untrusted data; they are never HTML,
  shell, URL, or terminal input.
* `byte-statistics` streams the whole object and calculates Shannon entropy in
  bits per byte (`-sum(p * log2(p))`), unique-byte count, NUL fraction and
  printable-byte fraction. Entropy is a fact, not a malware score.
* `generic-metadata` runs Debian `libimage-exiftool-perl` ExifTool 13.25 in
  JSON mode under the existing read-only, no-network bubblewrap boundary.
  Namespaced `metadata.exiftool.*` observations preserve the original tag and
  bounded value. Filesystem directory paths are omitted and `SourceFile` is
  reduced to a basename. Unsupported/binary inputs are `not-applicable`, not
  analyzer failures; timeout, isolation and malformed output remain errors.
* `similarity` runs Debian `ssdeep` 2.14.1. A fingerprint is an observation
  containing the algorithm, implementation result and source SHA-256. Small or
  low-variation inputs may be `not-applicable`. TLSH was evaluated and is
  deferred because no suitable Debian 13 package was available.

Cryptographic identity remains SHA-256 (with BLAKE3, SHA-1 and MD5 fixity
observations). Similarity fingerprints never participate in CAS identity,
deduplication, quarantine paths, or idempotency. M1.3 does not perform global
similarity search or RAB correlation.

`static-default@1` contains `identity`, `basic-metadata`, `file-type`,
`strings`, `byte-statistics`, `generic-metadata`, and `similarity`.
`security-default@1` and `identification-default@1` are unchanged. A static
profile normally returns `verdict: null`; generic characteristics cannot create
MALICIOUS, SUSPICIOUS, or PUA results.

Normalized observations are bounded before entering the result envelope. Raw
external-tool output is stored through the existing content-hashed opaque raw
output store. Partial results are valid: an ExifTool `not-applicable` result or
tool error does not discard successful hashes, type evidence, strings, entropy,
or similarity observations.
