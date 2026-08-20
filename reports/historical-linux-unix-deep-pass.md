# AVBox Historical Linux/Unix Deep Pass

Generated: 2026-08-20 UTC

## Executive summary

This preservation-only pass found one live, exceptionally fragile commercial
family: Comodo Antivirus for Linux 1.1.268025.1. Three original packages were
preserved immediately. The fourth, the i386 RPM, returned 404 even though
Comodo's own release post still publishes its exact size, MD5 and SHA-1.

Sophos still advertises SAV Linux/UNIX 9.17.4, but the exact installer URL now
returns an export-compliance/reCAPTCHA HTML interstitial to unattended clients.
The 9,430-byte response is retained as immutable source evidence and explicitly
is not classified as an installer. A validated retry is in the failure log. No
export control, account, authentication, or TLS control was bypassed.

All redistribution rights remain `unknown`. No antivirus software was unpacked,
installed, mounted, or executed.

## Emergency acquisitions

- **PRESERVED** `CAV_LINUX-1.1.268025-1.x86_64.rpm` from Comodo.
- **PRESERVED** `cav-linux_1.1.268025-1_i386.deb` from Comodo.
- **PRESERVED** `cav-linux_1.1.268025-1_amd64.deb` from Comodo.
- **PRESERVED** Comodo's release announcement and mutable download selector.
- **DEAD_SOURCE / ARTIFACT_WANTED** `CAV_LINUX-1.1.268025-1.i386.rpm`:
  official URL returned 404; exact published fingerprints are in the future-RAB
  manifest.
- **ARTIFACT_WANTED** Sophos `sav-linux-9-i386.tgz` 9.17.4: the official page
  advertises 350 MB, but unattended retrieval returns only an export-compliance
  interstitial.

## Sophos

**PRESERVED** primary release/EOL evidence establishes:

| Product | Engine | Threat data | Date/status |
|---|---|---|---|
| SAV Linux 7.6.7 | 3.47.1 | 4.93 | September 2013 |
| SAV Linux/UNIX 9.17.2 | VE 3.84.0 | unknown | Linux EOL 2022-08-31; UNIX EOL 2022-10-31 |
| SAV Linux/UNIX 9.17.3 | VE 3.85.1 | unknown | EOL 2023-07-20 |
| SAV Linux/UNIX 9.17.4 | VE 3.86.1 | unknown | EOL 2023-07-20 |

The official download page identifies Linux `sav-linux-9-i386.tgz` for Intel
and AMD64, plus UNIX 9.17.4 packages `sav-aix-9-powerpc.tgz`,
`sav-hpux-9-ia64.tgz`, `sav-solaris-9-i386.tar`, and
`sav-solaris-9-sparc.tar`. These are **LOCATED**, not preserved binaries; the
same export-compliance control applies and no bypass was attempted.

The SAV 9 guide documents `savupdate`, an hourly local cache/CID, the IDE
directory `/opt/sophos-av/lib/sav`, monthly VDB threat data, and separately
issued `.ide` files. Sophos staff documented that IDE hashes are carried in
CID/SDDS metadata and signatures are verified against `vdl.dat`. No official
historical VDB/IDE snapshot was exposed as a standalone unauthenticated object.
Status: **ARTIFACT_WANTED**.

The two official SAV 9 PDF endpoints repeatedly timed out from the VM; those
failures are preserved. The official 7.6.7 release notes were preserved.

## F-PROT

FRISK/F-PROT distribution infrastructure is dead. No mirror was used.

- `fp-linux-ws-4.4.2.tar.gz` is retained only as an insufficiently corroborated
  candidate fingerprint; version, size and hashes remain unknown.
- A 2015 independent test records exact x86-64 filename
  `fp-linux.x86.64-ws.tar.gz`, vendor trial path
  `http://www.f-prot.com/download/trial`, CLI `fpscan`, and updater `fpupdate`.
- Historical evidence identifies F-PROT 6.0.2 in an earlier Linux workflow, but
  does not establish that it was the final release.

Status: **ARTIFACT_WANTED** for final x86/x86-64 distribution and matching
definition files. These are future preservation-mirror targets, not guessed
official downloads.

## Bitdefender

**PRESERVED** official Scanner for Unices datasheet. It establishes Linux and
FreeBSD, x86/i686/amd64, RPM/DEB/generic `.tar.run` packages, and automatic or
manual product/definition updates. It does not identify the final release.

The exact filename
`BitDefender-Antivirus-Scanner-7.7-1-linux-amd64.deb.run` is corroborated by an
independent 2015 test. Version 7.6-4 remains a family lead, not an exact
fingerprint. No live official installer or standalone definition snapshot was
found. Status: **ARTIFACT_WANTED**.

## McAfee/Trellix

**PRESERVED** official VirusScan for UNIX 4.32.0 product guide.

| Platform | Officially documented 4.32.0 target | Exact package |
|---|---|---|
| AIX | 4.2.1, 4.3.x, 5.0L | unknown |
| FreeBSD | 3.2, 4.3 Intel 32-bit | unknown |
| HP-UX | 10.20, 11.x, 11i | unknown |
| Linux x86 | kernels 2.0/2.2/2.4, libc6; old/new libstdc++ variants | unknown |
| Linux S/390 | SuSE 7.2 | unknown |
| SCO | OpenServer 5, UnixWare 7.1.1 | unknown |
| Solaris SPARC | 2.5.1, 2.6, 7, 8, 9 | unknown |

The guide uses `vsun4320.tar.Z` as an example distribution filename but does not
bind it to one platform. The Trellix storage path containing `aix/4320` is not
enough to claim the example filename is AIX-specific.

For updates, the guide specifies 4.x DAT archives (`dat-nnnn.zip` / tar
variants), but explicitly warns that later DATs are not guaranteed compatible
with previous product versions. Therefore preserved DAT/XDAT 11880 compatibility
with VirusScan UNIX 4.32.0 is **UNVERIFIED**; no maximum compatible DAT version
was established.

## Dr.Web

The previously preserved official 6.02 manual establishes universal x86/x86-64
and native RPM/DEB packaging, Linux/FreeBSD/Solaris support, VDB databases and
`update.pl`. Official repositories/documentation remain live, but historical
binaries and usable keys are tied to vendor licensing/download workflows. No
account was created. Status: **ARTIFACT_WANTED** for original 6.02 and 10.x
packages plus contemporaneous VDB snapshots.

## ESET

**PRESERVED** ESET's EOL page. It distinguishes NOD32 Antivirus for Linux
Desktop (version 4 and earlier) from Endpoint Antivirus and Server Security,
states the desktop product is no longer downloadable or activatable, and states
application updates ended after 2022-08-03. Exact final build, filenames,
architectures and module/signature versions remain unknown. Status:
**ARTIFACT_WANTED**.

## Avira

Existing official evidence confirms VDF FuseBundle/manual downloads were
withdrawn. No primary-source exact final AntiVir Linux/Unix installer fingerprint
or compatible VDF snapshot was established. Status: **ARTIFACT_WANTED**; do not
conflate Windows FuseBundle evidence with a proven Linux package relationship.

## AVG

**PRESERVED** the official AVG 2011 Anti-Virus for Linux/FreeBSD manual. It
establishes a native product family and update mechanism, separate from Windows
AVG 18.8. Exact final installers and definitions remain **ARTIFACT_WANTED**.

## Avast

Official current Linux documentation identifies public i386/x86-64 package
repositories, signed incremental VPS9 updates, and a mirrorable VPS repository.
That documentation endpoint returned 503 during preservation. This is evidence
for current/business lineage only; it does not prove compatibility with an older
consumer/server package. Historical installers and final compatible VPS remain
**NEEDS_RESEARCH**.

## Kaspersky

Official evidence establishes Kaspersky Endpoint Security 10 for Linux
10.0.0.3458, released 2017-05-15, with vendor-server or local-folder database
updates. It is not evidence of a final historical release or standalone database
snapshot. Older Linux/Unix families, package names and definition cut-offs remain
**NEEDS_RESEARCH / ARTIFACT_WANTED**.

## Trend Micro

Existing IWSVA 6.5 SP1 documentation remains preserved. ServerProtect for Linux
documentation covers 2.5 and multiple 3.0 platform generations, scan engines,
ActiveUpdate and pattern files. The old 2.5 PDF endpoint still loops on redirects.
No exact live OPR/pattern object was resolved, so none was guessed. Status:
**PRESERVE_SOON** for exact Update Center objects.

## Norman

No adequate official evidence for a specific native Norman Linux/Unix scanner,
package, or definition set was established in the bounded census. Status:
**DOCUMENTED_ONLY / NEEDS_RESEARCH**.

## Comodo

Comodo's live page still targets Ubuntu 12.04, RHEL 5.9/6.3, Fedora 17, SLES 11,
openSUSE 12.1, Debian 6, CentOS 5.x/6.x and Mint 13 on 32/64-bit systems. The
official 2013 release post supplies exact URLs and published checksums. Three
packages were preserved; one disappeared. Definition database/version and update
protocol remain unknown because packages were not unpacked or executed.

## Historical definition sets

No new standalone historical definition bytes were preserved. Definitions remain
first-class wanted objects: Sophos VDB/IDE/SDDS, F-PROT definitions, Bitdefender
virus databases, McAfee 4.x DAT qualified to engine, Dr.Web VDB, Avira VDF,
AVG Linux updates, Avast VPS, Kaspersky databases and Trend OPR/pattern files.
Compatibility relationships are not asserted without primary evidence.

## Exact artifact fingerprints

Machine-readable fingerprints, with nulls for unknown fields, are in
`rab-future-acquisition.yaml`. Important exact identities are Sophos
`sav-linux-9-i386.tgz`, F-PROT `fp-linux.x86.64-ws.tar.gz`, Bitdefender
`BitDefender-Antivirus-Scanner-7.7-1-linux-amd64.deb.run`, McAfee
`vsun4320.tar.Z`, and the four Comodo 1.1.268025.1 packages.

## Artifact-wanted list

1. **EMERGENCY** authorized acquisition of genuine Sophos 9.17.4 Linux and UNIX
   objects before the vendor listing disappears.
2. **EMERGENCY** Comodo i386 RPM from a qualified preservation mirror using the
   published MD5/SHA-1/size fingerprint.
3. **PRESERVE_NOW** historical Sophos VDB/IDE snapshots and F-PROT final Linux
   distributions/definitions.
4. **PRESERVE_NOW** Bitdefender 7.7-1 platform packages and matching database.
5. **PRESERVE_SOON** McAfee 4.32.0 per-platform distributions with a qualified
   DAT cutoff; Trend OPR/pattern; Dr.Web 6.02 packages/VDB.
6. **PRESERVE_SOON** ESET Linux Desktop v4, AVG 2011, Avira, Avast, Kaspersky,
   and Norman exact artifacts after primary fingerprints are established.

## Dead endpoints

- Comodo i386 RPM URL: HTTP 404 on 2026-08-20.
- F-PROT/FRISK public distribution infrastructure: unavailable.
- ESET Linux Desktop: vendor states downloads/activation unavailable.
- Avira FuseBundle: vendor states it is no longer offered.

## Mutable endpoints

- Sophos endpoint download listing and fixed-package EOL pages.
- Comodo Linux download selector.
- Avast Linux package/VPS repositories.
- Trellix 4.x DAT/XDAT directories already tracked by the previous pass.

## Fragile endpoints

- Sophos installer URLs now interpose export compliance/reCAPTCHA.
- Three surviving Comodo HTTP package URLs; the sibling i386 RPM is already 404.
- Sophos historical PDF endpoints timed out twice.
- Avast Linux technical documentation returned HTTP 503.
- Trend ServerProtect 2.5 documentation redirect loop.

## Future RAB acquisition targets

The future-RAB manifest separates exact known artifacts from product-family
research targets and original vendor sources from future preservation-mirror
sources. No speculative filename is promoted to an exact artifact. Open-source
baseline locations remain recorded but were not mirrored; none appeared newly
endangered relative to the commercial targets.
