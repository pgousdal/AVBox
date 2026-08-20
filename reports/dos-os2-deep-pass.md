# AVBox DOS + OS/2 historical antivirus deep pass

Research and acquisition date: 2026-08-20 UTC. This is preservation metadata,
not scanner qualification. No acquired program was installed, unpacked, mounted,
or executed. `redistribution_rights` remains `unknown` unless separately proven.

## Executive summary

The emergency result is **PRESERVED**: McAfee VirusScan Command Line 4.3.20,
engine 4320, for DOS 6.22 and documented Windows platforms was found in an open
official Trellix directory and acquired immediately. Its vendor README says the
package includes DAT 4307 and accepts DAT 4297 or later. The engine-only
SuperDAT, product guide, two readmes, and a snapshot of the mutable directory
were also preserved. This establishes a precise DOS tuple, but does **not**
establish compatibility of current DAT 11880 with DOS or OS/2.

IBM's live master index and the only remaining object in its now-empty `ibmav`
directory were preserved. The notice points at `http://www.av.ibm.com`; that
address now redirects to IBM's generic home page rather than serving signatures.
The official IBM brochure was reacquired from a second URL and deduplicated by
SHA-256, retaining the new provenance event.

No additional official, unauthenticated DOS/OS2 program or historical definition
set was verified live. Candidate versions below remain candidates unless marked
vendor-confirmed. Third-party locations are leads for future RAB qualification,
not original sources.

## Emergency acquisitions

| Object | Exact official URL | Size | SHA-256 | BLAKE3 |
|---|---|---:|---|---|
| McAfee VirusScan Command Line 4.3.20 / engine 4320 / bundled DAT 4307, `cmz4320l.zip` | `https://downloadcenter.trellix.com/products/licensed/superdat/engine/intel/4320/cmz4320l.zip` | 6,051,226 | `c2d10998619bee32b4645b9228f7d127ae3b991d2c4dab7e5a93ea0c154b8bbf` | `b612ce771f0a8354069f8e15de9faeb4a1713c5ab0ef493004fba7e58375062e` |
| McAfee engine-only SuperDAT 4320, `4320eng.exe` | `https://downloadcenter.trellix.com/products/licensed/superdat/engine/intel/4320/4320eng.exe` | 3,598,613 | `5b3cc2dcfd384c620869d3c5e70583dfdd729000dbada1cd07eb813e2e7a9ff0` | `6bfeb33527de6f7a232009e4a6dfa182a1cc437210e99ddb8a517b0f1943fb6f` |
| Command-line README | `https://downloadcenter.trellix.com/products/licensed/superdat/engine/intel/4320/readme_cmz.txt` | 18,444 | `cc3ddecc83db16a9f6231ea97c017ec1ec11c3888d7a1e3f498c980e7e78be11` | `9be6b5fac219d8d7a4f54ace8e2e0bf38ee492bc20e16c96d924c5a4c64270bb` |
| Engine SuperDAT README | `https://downloadcenter.trellix.com/products/licensed/superdat/engine/intel/4320/readme_sdat.txt` | 23,934 | `e4c78be5fb37e5338232dde3d536b79170770ed1ec8f45d6f958a5eb43c2257d` | `04336796d7f6ec89fea2acead74dd3c99bd2a5638199c89cf670c0b359bdda35` |
| Command-line product guide | `https://downloadcenter.trellix.com/products/licensed/superdat/engine/intel/4320/e4320wpg.pdf` | 1,089,383 | `18ca49b20489d836e0f974230f8257f98bfa653ca738f1e0c4877689901be874` | `b665dc7fe99b23765c20d12e6b7b5f7aac8523e748e34f4828497eb31dfe5443` |
| Mutable Trellix 4320 directory snapshot | `https://downloadcenter.trellix.com/products/licensed/superdat/engine/intel/4320/` | 1,255 | `f0ed838cc79b2a677ba3e5b331e1d9d94d36ba01d4dc2fa4b6a23e65c18fcc58` | `921acf5a23ed2faf086ba642f416194db44d1599c67e8bbbcd693a8f2159e4c6` |
| IBM PS products master index | `https://public.dhe.ibm.com/ps/products/INDEX.TXT` | 10,884,924 | `7a58048877d67d7f853bb1544082d7be8410876e96a96b792d9fb6241c80590b` | `04464b7e8c2e0940d20c4b933a20c960c0c80d96cec359dd814894f6267df453` |
| IBM `ibmav` retirement notice | `https://public.dhe.ibm.com/ps/products/ibmav/.message` | 575 | `4af555f70ec3d449b6f393b8d3e1783aca71c67a58ca75367d8888248e9dccf3` | `a60443b1c6d89cb229fd31e409edf9c3b8148871c82111626cb0012a011dad3f` |
| Retired IBM signature-service redirect evidence | `http://www.av.ibm.com/` | 199,506 | `6c8f62189d551eac81697e5365d8fa599f1340a0190a46e6a497a6ba8c1c58c7` | `dd08b67c349465a840c2c8ca5d6f898c79c529f607c721a9015b99a5be9c124a` |

The IBM AntiVirus brochure at
`https://public.dhe.ibm.com/software/security/antivirus/about/antivirus.pdf`
matched the already-preserved IBM-hosted object SHA-256
`d260827bdcdc7b0e4d9b55600ace10a649462211560f8e9e9e076ae28ee8190d`;
only a new acquisition event was appended.

## DOS

### McAfee

**PRESERVED.** Primary release notes identify product 4.3.20, engine 4320,
bundled DAT 4307, minimum DAT 4297, Intel protected-mode `SCANPM.EXE`, and DOS
6.22. They list `SCAN.EXE`, `SCANPM.EXE`, `CLEAN.DAT`, `NAMES.DAT`, and
`SCAN.DAT`. This exact tuple is the best-qualified DOS combination from the
pass. The adjacent `4320eng.exe` readme names supported Windows products, not
OS/2; no OS/2 relationship is inferred.

### F-PROT

**ARTIFACT_WANTED.** A qualified historical lead identifies 3.16f as the late
DOS line and the definitions `SIGN.DEF`, `SIGN2.DEF`, and `MACRO.DEF`. The final
package filename, engine build, updater, final definition date, sizes, and
hashes remain unknown. FRISK infrastructure is dead; no mirror bytes were used.

### Dr Solomon

**DOCUMENTED_ONLY.** Native DOS and OS/2 product families are established, but
neither a primary final-DOS release tuple nor an exact distribution/database
fingerprint was recovered. “7.74 OS/2” remains a candidate, not a confirmed
exact artifact.

### ThunderBYTE

**ARTIFACT_WANTED.** TBAV is confirmed as a DOS-focused heuristic/signature
product, discontinued after acquisition by Norman. “8.11” remains a candidate
until a primary manual/readme or qualified original-media fingerprint confirms
the version and distribution name. `Anti-Vir.Dat` is reported as integrity
tracking data; its exact role must not be conflated with signatures.

### Norton

**DOCUMENTED_ONLY.** The DOS lineage and early releases are established, but a
final native-DOS release/definition tuple was not established without mixing in
later Windows LiveUpdate products. No Symantec DOS definition endpoint was
qualified.

### Central Point and Microsoft MSAV

**DOCUMENTED_ONLY.** MSAV and VSAFE are media-dependent components of MS-DOS
6.x. They should be represented as extracted components related to exact RAB/WTM
OS media, not by duplicating complete MS-DOS media in bootstrap. Exact per-media
component versions and the Central Point relationship require primary evidence.

### IBM

**ARTIFACT_WANTED.** Official IBM service metadata proves IBM AntiVirus 2.3 and
2.4 update identifiers `AV23x` and `AV24x`. The old official binary directory is
empty. Candidate milestones 1.02, 1.03, 1.04, 1.06, 2.0, 2.1, 2.2, 2.4, 2.5,
and 3.0 are retained for individual announcement/media validation, not asserted
as one verified release matrix.

### AVP/Kaspersky, VET, Sophos, Norman and other DOS targets

**NEEDS_RESEARCH / DOCUMENTED_ONLY.** Credible family-level leads exist for
AVP/Kaspersky, VET, Sophos SWEEP, and Norman, but no exact official distribution
plus matching definition tuple was established. Linux Sophos IDE evidence is
not compatibility evidence for DOS. No credible native DOS NOD32/ESET artifact
was found, so no DOS lineage is asserted.

### Integrity Master and InVircible

**DOCUMENTED_ONLY.** Preserve these as integrity/heuristic or system-detector
research targets unless primary evidence demonstrates a conventional signature
AV role. Exact final artifacts and update models remain unresolved.

### Dr.Web

**LOCATED / NEEDS_LICENSE.** Doctor Web still officially advertises its DOS 386
and OS/2 console scanners and says they can run without installation from
removable media. The download route requires a request workflow. No account was
created and no package was obtained. VDB is a documented Dr.Web database format,
but current VDB compatibility with an unidentified DOS engine remains unknown.

## OS/2

### IBM AntiVirus

Official evidence currently supports this partial matrix:

| Release | Evidence | Artifact result |
|---|---|---|
| 2.3 | IBM service page: update family `AV23x` | `ARTIFACT_WANTED`; live directory empty |
| 2.4 | IBM service page: update family `AV24x` | `ARTIFACT_WANTED`; live directory empty |
| other candidate milestones | qualified historical leads only | `NEEDS_RESEARCH`; do not treat as exact |

The official brochure describes DOS, Windows, and OS/2 availability, but does
not prove that their engines or definitions were byte-identical. Shared
definition/updater relationships therefore remain **unknown**.

### McAfee VirusScan

| Release | Engine/DAT evidence | Artifact result |
|---|---|---|
| 4.0.2 build 4009 | Reproduced original README says bundled DAT 4009 works only with 4.0.xx engines, not 2.x/3.x | `ARTIFACT_WANTED`; exact package name/hash unknown |
| 4.0.4 | Native release/readme dated 2001-04-12 is a strong secondary lead | `ARTIFACT_WANTED`; engine and DAT unknown |

Native filenames listed by the reproduced 4.0.2 readme include `OS2SCAN.EXE`,
`PMSCAN.EXE`, `PTOOLKIT.EXE`, `VSHIELD.FLT`, and the three DAT files. This is
not an original vendor download. DAT 4009 is the newest exact OS/2-compatible
DAT established in this pass. Neither current DAT/XDAT 11880 nor the preserved
DOS engine-4320 tuple proves OS/2 4.0.2/4.0.4 compatibility.

### Dr Solomon, Norton, F-PROT and Dr.Web

- Dr Solomon OS/2 7.74: **candidate / ARTIFACT_WANTED**, exact media unresolved.
- Norton AntiVirus OS/2 5.03.69: **ARTIFACT_WANTED**. A reproduced September
  2000 README identifies native support for OS/2 2.11 and Warp 3/4 on 386 PCs;
  exact media and definition identities remain unknown. Candidate 5.02 remains
  unverified.
- F-PROT Professional OS/2: **ARTIFACT_WANTED**. Native package, release and
  cross-platform definition sharing remain unresolved.
- Dr.Web OS/2: **LOCATED / NEEDS_LICENSE** on current official infrastructure;
  exact version/package and compatible VDB are unavailable without the vendor
  request path.

### Other native scanners

Sophos, AVP/Kaspersky, Norman and VET remain **UNVERIFIED** as native OS/2
products in this pass. DOS execution under OS/2 is not counted as native.

## Historical definitions and engine compatibility

| Engine/product | Established definition relationship | Confidence |
|---|---|---|
| McAfee VirusScan Command Line 4.3.20 / engine 4320 | bundled DAT 4307; accepts 4297 and later | primary vendor README |
| McAfee VirusScan OS/2 4.0.2 build 4009 | bundled DAT 4009; 4.0.xx engines only | reproduced original README; original package wanted |
| IBM AntiVirus DOS/OS2 | `AV23x` and `AV24x` update families exist | primary IBM service index; contents unavailable |
| F-PROT DOS | `SIGN.DEF`, `SIGN2.DEF`, `MACRO.DEF` definition structure | qualified historical lead; terminal snapshot unknown |
| Dr.Web DOS/OS2 | VDB family applies to Dr.Web products generally | official family evidence; historical engine compatibility unknown |

No historical definition timeline was bulk mirrored. The only newly secured
historical definition bytes are those bundled, unopened, inside the exact
`cmz4320l.zip` distribution; they are not claimed as independently extracted
objects.

## Exact artifact fingerprints and wanted list

Machine-readable status is in `rab-future-acquisition.yaml`. Exact preserved
fingerprints are in the acquisition manifest/events. Highest-priority wanted
objects are:

1. Original VirusScan for OS/2 4.0.2 build 4009 package and its bundled DATs.
2. Original VirusScan for OS/2 4.0.4 package plus engine and final proven DAT.
3. IBM `AV23x`/`AV24x` update objects and original 2.3/2.4 DOS/OS2 media.
4. F-PROT DOS 3.16f distribution and final compatible DEF snapshot.
5. Exact F-PROT Professional OS/2 distribution/DEF tuple.
6. Norton AntiVirus OS/2 5.03.69 original media and final definitions.
7. Dr Solomon OS/2 candidate 7.74 and final DOS distribution/database tuple.
8. TBAV final DOS distribution and signature/integrity data.
9. Versioned Dr.Web DOS 386/OS2 package and evidence-matched VDB snapshot.
10. Primary evidence and bytes for final Norton DOS, Sophos DOS SWEEP,
    IBM DOS, AVP DOS, VET DOS, Integrity Master, InVircible, and Norman DOS.

## Dead, fragile and mutable sources

- **DEAD_SOURCE:** IBM's former `ibmav` directory contains only a retirement
  notice; `av.ibm.com` redirects to IBM's generic home page and no longer acts
  as the signature service.
- **FRAGILE:** Trellix's open engine-4320 directory contains original 2003
  packages adjacent to legacy trees that have already lost individual objects.
- **MUTABLE:** Trellix directory indexes and current 4.x DAT/XDAT endpoints.
- **DEAD_SOURCE:** FRISK/F-PROT original distribution infrastructure.
- **NEEDS_LICENSE:** Doctor Web's still-advertised DOS/OS2 scanner download
  requires a request flow; no control was bypassed.

Two failed IBM attempts were retained as evidence: an absent Content-Type caused
safe rejection of the 575-byte notice, and a subsequent resume received HTTP
416 before the validated clean retry succeeded. TLS validation remained enabled.

## Future RAB sources

For dead original sources, NVG, Internet Archive software/media collections,
Hobbes/OS2 archives, OS2World/eCSoft local copies, and qualified historical FTP
mirrors are recorded only as `future_source_candidate` leads. RAB must verify
media provenance and hashes; their availability does not make them original
vendor sources or establish redistribution permission.

## Verification and RAB readiness

Complete verification passed for **44/44 immutable objects**, checking byte
size, SHA-256, SHA-1, MD5, and BLAKE3. The store contains **46 acquisition
events** (including deduplicated provenance) and **15 failure events**, with
1,323,417,669 artifact bytes. A fresh RAB export passed independent verification
for all 44 objects and includes bytes, manifests, acquisition/failure/integrity
logs, rights and compatibility metadata.

The preservation volume reports 33,501,757,440 bytes total,
1,326,149,632 used and 30,440,845,312 available (5% used; approximately 28.35
GiB free). It remains a separate libvirt volume and is independently reusable if
the VM OS disk is rebuilt.
