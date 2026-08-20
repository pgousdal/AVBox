# AVBox old-Windows historical antivirus deep pass

Research/acquisition date: 2026-08-20 UTC. Scope: Windows 3.1, WfW 3.11,
Windows 95, Windows 98/98SE/ME, Windows NT 3.51, NT4, and Windows 2000.
Nothing acquired was installed, unpacked, mounted, or executed. Candidate values
are not final-version claims. Redistribution rights default to `unknown`.

## Executive summary

The emergency discovery was an open official Trellix/Network Associates AVERT
tree containing original 1998 platform-specific engine/DAT hotfixes. Four exact
tuples were preserved immediately:

- Win3.x: VirusScan 3.2.1 hotfix, native Win16 engine components, DAT 3110.
- Windows 95/98: VirusScan 3.2.1 hotfix, Win9x engine/VxD, DAT 3110.
- Windows NT Intel: VirusScan/NetShield 3.2.1, kernel driver, DAT 3110.
- Windows NT DEC Alpha: VirusScan/NetShield 3.20a, DAT 3109.

The same archive yielded RMVclean 4.01.14 for Excel 95/97, an exact but not yet
fully qualified Dr Solomon `avtk-789.zip`, a definition/update candidate
`3010-98.zip`, and a Windows 98 distribution candidate `v98i400d.zip`. Exact
bytes were preserved before semantic qualification because the official archive
is fragile and neighboring legacy objects have disappeared independently.

No non-McAfee vendor exposed another verified, public, unauthenticated old-
Windows binary that met the acquisition threshold. Unknowns remain null in
`old-windows-final-matrix.yaml`; widely repeated version claims are retained only
as candidates.

## Emergency acquisitions

| Artifact | Established identity | SHA-256 | BLAKE3 |
|---|---|---|---|
| `wsc-321.zip` | Win3.x VirusScan 3.2.1 hotfix, DAT 3110 | `eddaeee3058baae4b4e2a731e47447a8fe6e6682f5f26065d86a7893e5baea09` | `73978ab30f894647957bc3099d214a665968e60cb6b97e303755a15fc00458e4` |
| `9xup321.zip` | Win95/98 VirusScan 3.2.1 hotfix, DAT 3110 | `a596c271113ea4f70ce9fe7182317deb8f60caf810b667f9f5c661f7975778cc` | `0ebb3b5dd98c183d80b70a577cc11ee5eb92f718e8f6ff730ce071874e5f6c24` |
| `ntup321.zip` | NT Intel VirusScan/NetShield 3.2.1, DAT 3110 | `0df7612b70baa8d2e19c36d689b669c74506edef2406a2c34a8793d63152d990` | `5199570222817322b7619104c21a95b82a3e05335a30d0696ccff387c1d0ea08` |
| `ntup320a.zip` | NT DEC Alpha 3.20a, DAT 3109 | `185e36fd0f174d3e96322cfdc768f15b33493b3df0e6b163fe33ad59efdc92fd` | `97b12c11be65a4430e44b425c03441d46a69292dd21bfbb5b89b5e12ece6f720` |
| `rmvclean40114.zip` | RMVclean 4.01.14 macro remover, Excel 95/97 | `5fe3b83c8e025c0d3494a2cf5c3ac2008678a0d44853863a10bb95642be11130` | `86975fb770341ee914d01183c03c29ed37ccf074f9fd844ced577d590493fe1b` |
| `avtk-789.zip` | Dr Solomon candidate; exact version/platform unresolved | `05677bc9eae37bd9a7af1e7d45ae7567798fe84fa5e69e0fc047f644c582117c` | `a893553b2ef573f869e3c15c4df0bb55caeb19ccc8deb7bce27ddccd70a77ef1` |
| `3010-98.zip` | McAfee definition/update candidate; DAT semantics unresolved | `78a767fd23899b98585252441d36e28d8af588a6d800c148d13c1b739adc75d8` | `70a70476873323503f92da4086e92919d623efeda847f55611d0e01f74dfefb3` |
| `v98i400d.zip` | VirusScan Win98 Intel candidate; exact build unresolved | `d46f2dc995d5ca89295904882439499185c23b08c07c160538d46774f2a6ff11` | `ce280267f815dcd204decc5704463e920d93c0e9445a09812734097e55b542ca` |

Preserved provenance documents:

| Evidence | SHA-256 | BLAKE3 |
|---|---|---|
| VirusScan update page | `3a845f3646dd440a09a814a197f59ae52f4c13fd7b677a7e947472f379179411` | `6408d4bb0bd669a1da4089065203a1e6ca16ace02148179e416db7c3e68b0194` |
| Platform-hotfix directory | `a0bc8b03a7c0425dd5b421d40d7a92802d259e83d4718182cf5be8b2e4aa9971` | `b057ffcc50851a8d82377648369cd530e6e2186240b5cd54332643b994c4d999` |
| AVERT standalone directory | `2182f0ff208a64b661ba8831afa1e63cf6718783c9814711f7818c1ae9bf67fd` | `0fd2573f6216cf9830f8ff5f9f9a311f5c91dd6e7e8e0ce23125f4646f04e611` |
| RMVclean vendor page | `cd54471ea84a67b8bf319c889c9e40764c930d227010ea5e581d2227533de42f` | `0794ef062dead6a28971de326b518f8b310dca3266a01cf044cc29cd99a80bb9` |

All source URLs and HTTP metadata are in acquisition events. The common roots
are `https://downloadcenter.trellix.com/products/mcafee-avert/stand_alone/`
and its directly indexed `new/`, `new/dec/`, and `archive/` children.

## Windows 3.1 / WfW 3.11

**Strongest tuple:** McAfee VirusScan Windows 3.x engine hotfix 3.2.1 with DAT
3110. Vendor instructions name native Win16 `MCSCAN16.DLL` and `VSHIELD.386`,
separating it from a DOS scanner launched under Windows. `wsc-321.zip` is a
patch/update, not the base installer, so the complete product remains wanted.

Norton native Windows 3.1 support is established by the IBM-hosted brochure,
but its final Win16 release, engine and definition set remain unknown. Dr
Solomon, F-PROT Professional, Sophos/SWEEP, TBAV, Central Point/PC Tools, IBM
AntiVirus, AVP, VET and Norman retain family-level targets; candidate versions
such as TBAV 7.07 and Dr Solomon 6.13Z are not promoted without primary evidence.

## Windows 95

McAfee 3.2.1/DAT 3110 is preserved as a period candidate. The official 4.5.1
release guide confirms Windows 95 compatibility but does not establish finality
or a final DAT. Norton, PC-cillin, AVP, F-PROT, Sophos, Norman, VET, Avast, AVG,
Avira, Bitdefender, Panda and CA/eTrust final tuples remain wanted.

## Windows 98 / 98 SE / ME

McAfee 3.2.1/DAT 3110 is preserved for Windows 98; 4.5.1 is officially
documented for Windows 98 and ME. VirusScan Command Line 4.3.20/engine 4320/DAT
4307 is separately preserved and officially lists Windows 98 and ME, making it
a future `MAXIMUM_RETRO` candidate—not a qualification result. The official
`v98i400d.zip` bytes are preserved as a candidate pending exact readme/media
identity. Windows 98 SE was not named separately by these sources.

Avast 4.8, AVG 7.5, Norton 2005, PC-cillin 2005, Norman 5.x, Bitdefender 7.x,
Panda Titanium/Platinum and CA/eTrust are retained as research candidates only.
No current Avast VPS18 or AVG 18.8 artifact is related to Win9x by inference.

## Windows NT 3.51

McAfee's preserved Intel and DEC Alpha packages establish architecture-specific
native NT engines and `MCSCAN.SYS` filter-driver components. The primary NT
manual covers NT 3.51 as well as NT4. Exact base installer, service level and
terminal compatible DAT remain wanted. Norton, F-PROT, Dr Solomon, Sophos,
PC-cillin NT and CA/InocuLAN lack exact final tuples.

## Windows NT 4.0

Period candidates are McAfee 3.2.1/DAT 3110 (Intel) and 3.20a/DAT 3109
(Alpha). VirusScan 4.5.1 requires NT4 SP4 or later. VirusScan Enterprise 7.0
officially retains NT4 while dropping Win9x; later NT4 finality remains
unresolved. Command Line 4.3.20/engine 4320/DAT 4307 is preserved as a separate
candidate. No claim is made that DAT 11880 works.

Norton/Symantec, ESET/NOD32 2.70, Dr.Web, Kaspersky, Sophos, Trend Micro,
CA/eTrust, Avast, AVG, Avira, Norman, Bitdefender and F-Secure remain exact-
tuple research targets. “Supported around 2006” is not enough to populate a
final matrix.

## Windows 2000

McAfee 4.5.1 and VirusScan Enterprise 7.0 have primary Windows 2000 evidence;
Command Line 4.3.20/engine 4320/DAT 4307 is preserved. Their shared version
number does not prove identical runtime binaries across GUI, command-line and
enterprise products. Current DAT 11880 remains only a preserved research input.

Windows 2000 SP4 plus Update Rollup 1 is retained as a likely qualification
baseline, not a universal product requirement. SEP 11, NOD32 2.70, Avast
8.0.1497, AVG 7.5, Avira 7, Bitdefender 2008, Dr.Web 4.44, Kaspersky 7,
Sophos 7, Trend OfficeScan, F-Secure 2008, Norman and CA/eTrust remain candidates
until product-specific primary evidence establishes exact builds and updates.

## Vendor findings

### McAfee / Trellix

| Platform | Product/engine | Definition | Status |
|---|---|---|---|
| Win3.x/WfW | VirusScan hotfix 3.2.1; `MCSCAN16.DLL`, `VSHIELD.386` | 3110 | `PRESERVED`; base product wanted |
| Win95/98 | VirusScan hotfix 3.2.1; `MCSCAN32.DLL`, `MCSCAN32.VXD` | 3110 | `PRESERVED`; base product wanted |
| NT3.51/NT4 Intel | VirusScan/NetShield 3.2.1; `MCSCAN32.DLL`, `MCSCAN.SYS` | 3110 | `PRESERVED`; base product wanted |
| NT3.51/NT4 Alpha | VirusScan/NetShield 3.20a | 3109 | `PRESERVED`; base product wanted |
| Win95/98/ME/NT4/2000 | VirusScan 4.5.1 | unknown | documentation preserved |
| Win98/ME/NT4/2000 | Command Line 4.3.20, engine 4320 | 4307 bundled; accepts 4297+ | `PRESERVED` |

The 4320 engine-only SuperDAT documentation lists Windows products but not
Win3.x or OS/2. Same engine version does not imply shared driver/runtime bytes.

### Norton/Symantec

Native Win3.1, Win95/98, NT and OS/2 family evidence is preserved. Consumer and
corporate lineages are kept separate. Final installers, engines, Intelligent
Updater/LiveUpdate definitions and SEP 11/Windows 2000 status remain wanted.

### Dr Solomon

`avtk-789.zip` is now preserved from official Network Associates infrastructure.
It remains a `CANDIDATE_ARTIFACT`: “7.89” and precise Windows generations are not
asserted solely from the filename. Earlier 6.13Z/later 7.x candidates require
media/readme qualification.

### F-PROT, Sophos, ThunderBYTE, Central Point and IBM

- F-PROT: Win3.x/Win9x/NT package and DEF-sharing relationships unresolved.
- Sophos: old-Windows IDE sharing/finality unresolved; Linux IDE evidence is
  not reused without proof.
- TBAV: Windows 7.07 remains a candidate; no official bytes found.
- Central Point/PC Tools: DOS-box CPAV remains distinct from native PC Tools for
  Windows integration.
- IBM AntiVirus: official brochure proves Windows-family availability, while
  the former IBM update directory/service is dead. Native versus DOS component
  and shared-definition boundaries remain unknown.

### AVP/Kaspersky, VET, Norman, Trend Micro, ESET and Dr.Web

AVP/Kaspersky transitions and exact old database formats remain unresolved.
VET and Norman have insufficient primary artifact fingerprints. Trend Micro's
official removal matrix establishes extensive PC-cillin/OfficeScan lineage but
not final OS-specific tuples or pattern compatibility. NOD32 2.70 and Dr.Web
4.44 remain candidates. Official Dr.Web documentation does support Windows 2000
SP4 plus Update Rollup 1 for an adjacent 6-era product, not retroactively for
4.44.

### Avast, AVG, Avira, Bitdefender, Panda, CA/eTrust and F-Secure

All remain `ARTIFACT_WANTED` or `NEEDS_RESEARCH` for these OS generations.
Candidate final versions are retained in the matrix only with low confidence.
No old official installer/definition object was validated live during this
pass, and no third-party proprietary binary was substituted.

## Historical definitions and compatibility

Definitions are first-class preservation objects. Newly preserved bundles carry
DAT 3110 or 3109 according to primary vendor pages; `3010-98.zip` is separately
preserved but remains semantically unqualified. The store already contains DAT
4307 inside the Command Line distribution and DAT/XDAT 11880. Compatibility is
not transitive:

- period candidates use evidence-bound product/engine/DAT tuples;
- final-historical candidates remain null unless normal vendor support is shown;
- maximum-retro entries are documentation candidates only, pending future
  disposable-runtime qualification.

## Service packs, drivers, macro tools and rescue media

The four McAfee hotfix packages are first-class `patch-for` objects. Primary
pages identify Win16 `VSHIELD.386`, Win9x `MCSCAN32.VXD`, and NT `MCSCAN.SYS`.
VirusScan 4.5.1 documents NT4 SP4+. No scanner was installed to inspect drivers.

RMVclean 4.01.14 and its page are preserved as a standalone Excel 95/97 macro
removal utility, not a full engine. The AVERT tree also lists rescue/boot tools,
but their identities and relationships were insufficient for indiscriminate
capture. No rescue media was generated.

## Exact fingerprints and artifact-wanted list

Exact preserved fingerprints are in the acquisition events; machine-readable
future targets are in `rab-future-acquisition.yaml`. Highest-priority wanted
objects are:

1. Base installers/media matching all four preserved McAfee 3.2.x hotfixes.
2. Final vendor-documented DAT for Win3.x, Win9x, NT3.51, NT4 and Windows 2000.
3. Exact identity/readme for `v98i400d.zip`, `3010-98.zip`, and `avtk-789.zip`.
4. Norton final Win16, Win95, Win98/ME, NT3.51/NT4 and Windows 2000 tuples.
5. Final Avast 4.x and AVG 7.x Win9x installers plus VPS/database snapshots.
6. Trend PC-cillin/OfficeScan engines plus matching historical OPR patterns.
7. F-PROT Windows packages plus compatible DEF snapshots.
8. Sophos Windows packages plus evidence-bound IDE snapshots.
9. NOD32, Dr.Web and Kaspersky NT4/2000 exact installers and databases.
10. CA/InocuLAN/eTrust, VET, Norman, Panda, F-Secure, Avira and Bitdefender
    primary fingerprints.

## Dead, fragile and mutable endpoints

- **FRAGILE / EMERGENCY:** Trellix AVERT `stand_alone`, `new`, and `archive`
  trees. They expose original 1998 bytes with no stability guarantee.
- **MUTABLE:** Trellix directory indexes and current DAT/XDAT endpoints.
- **DEAD:** IBM AntiVirus update directory/service, FRISK/F-PROT infrastructure,
  and previously recorded missing Trellix objects.
- **DEAD/UNRESOLVED:** historical Avast/AVG/Avira/Trend/ESET product-specific
  update paths were not guessed when no primary link survived.

Potential future RAB sources—Internet Archive, WinWorld, NVG, BetaArchive
metadata, vendor-CD/BBS archives, qualified FTP mirrors and OS/2 archives—are
only `future_source_candidate` leads. RAB must establish provenance and hashes.

## Final compatibility matrix and RAB readiness

`config/old-windows-final-matrix.yaml` distinguishes all eight Windows targets,
stores product/engine/definition fields separately, and leaves unknowns null.
It is research input, not proof that a scanner works.

Complete verification passed for **56/56 immutable objects**, checking byte
size, SHA-256, SHA-1, MD5 and BLAKE3. The store contains **58 acquisition
events**, **15 failure events**, and **1,341,811,319 artifact bytes**. A fresh
RAB export passed independent verification for all 56 objects and contains the
bytes, manifests, acquisition/failure/integrity logs, rights, relationships and
compatibility metadata.

The 33,501,757,440-byte preservation volume has 1,344,704,512 bytes used and
30,422,290,432 bytes available (5% used, approximately 28.33 GiB free). It
remains independent of the disposable VM OS disk.
