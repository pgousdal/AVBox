# M1.3 acceptance

M1.3 was qualified on the existing `avbox-m1-qualification` Debian 13.6
x86-64 VM. Debian packages installed by Ansible were:

* `libimage-exiftool-perl` 13.25+dfsg-1 (ExifTool 13.25)
* `ssdeep` 2.14.1+git20180629.57fcfff-3+b2 (ssdeep 2.14.1)

TLSH was not installed: no suitable Debian 13 package was available through
the accepted package source, so it remains explicitly deferred.

Real authenticated Protocol v1 `static-default@1` jobs completed for zeros,
PNG, ZIP, inert strings, and deterministic pseudo-random bytes. Representative
jobs:

* zeros: `49710da5-0468-4677-bf41-c177d882f1fe`, entropy 0, ssdeep present,
  ExifTool `not-applicable`, verdict null.
* PNG: `66d3e465-15e1-449f-9414-149f51209685`, ExifTool complete, MIME and
  metadata observations, ssdeep present, verdict null.
* ZIP outer object: `d90de55b-ee84-4dba-bd58-ec0659daabe6`, ExifTool complete,
  no child objects or member enumeration, verdict null.
* inert strings: `cd23e178-734c-4a9b-aa0b-7e80714efa1b`, bounded strings and
  ssdeep, ExifTool `not-applicable`, verdict null.
* deterministic high-entropy bytes: `c3dd0e8b-a81e-44b9-9608-6545dbc2d7a5`,
  entropy 8.0, bounded strings, ssdeep, verdict null.

Upload staging contained zero files after completion. Existing ClamAV/YARA
qualification and system-detector separation remained intact. Local tests,
Ruff, strict mypy, package build, registry validation, systemd verification,
and Ansible syntax are required before the milestone commit; a second Ansible
run must report `changed=0` and `failed=0`.
