# AVBox Preserve-Before-M0 Rescue Pass

Generated: 2026-08-20 UTC

Status vocabulary: `PRESERVED`, `LOCATED`, `PRESERVE_NOW`, `ARTIFACT_WANTED`,
`DOCUMENTED_ONLY`, `DEAD_SOURCE`, `NEEDS_LICENSE`, and `NEEDS_RESEARCH`.
Public availability does not establish redistribution rights. Unless primary
rights evidence says otherwise, `redistribution_rights` is `unknown`.

## Emergency acquisitions

- **PRESERVED** — McAfee/Trellix AVV DAT 11880, dated 2026-08-19, from the live
  official 4.x directory. The tar file was stored without opening it.
- **PRESERVED** — McAfee/Trellix XDAT 11880, dated 2026-08-19, and the exact
  live NAI directory response. The Windows executable was not run.
- **PRESERVED** — the mutable 4.x directory response that identified DAT 11879
  and 11880.
- **DEAD_SOURCE** — DAT 11878 returned 404 after a cached official index showed
  it. XDAT 11872 had already failed the same way. This infrastructure is
  rotating faster than discovery caches.
- **PRESERVE_NOW** — future rotating XDAT snapshots should use a fresh live NAI
  response and same-session ingest; no filename should be inferred.

## DOS

- **PRESERVED** — IBM-hosted Norton AntiVirus brochure documenting a DOS 5+
  scanner/product and separate Windows 3.1/DOS requirements.
- **PRESERVED** — McAfee SuperDAT documentation covering DOS and legacy McAfee
  4.x products, plus DAT 11880 as a definition candidate. Exact compatibility
  of DAT 11880 with each DOS engine remains unproven.
- **PRESERVED** — Doctor Web's official current product page explicitly retains
  a DOS 386 scanner and MS-DOS/OS2 product lineage.
- **ARTIFACT_WANTED** — final F-PROT/FRISK DOS distribution and signatures;
  McAfee SCAN engine matching a documented DAT; Dr Solomon, TBAV, Norton, Central
  Point, AVP, VET, Sophos, IBM, Integrity Master, InVircible, MSAV, Norman and
  versioned Dr.Web DOS media/definitions. No official binary was guessed.

## Windows 3.x

- **PRESERVED** — IBM/Norton primary evidence for a native Windows 3.1 product,
  distinct from the DOS-only installation option.
- **PRESERVED** — McAfee SuperDAT guide with Windows 3.1 compatibility evidence
  and DAT 11880 candidate bytes.
- **ARTIFACT_WANTED** — final native Win16 packages and matching definitions for
  Norton, F-PROT Professional, Sophos, AVP, VET, IBM, Norman, McAfee, TBAV, Dr
  Solomon and Central Point. Product media and DOS-in-Windows scanners must not
  be conflated.

## Windows 9x/ME

- **PRESERVED** — McAfee VirusScan 4.5.1 release guide documents Windows
  95/98/ME; SuperDAT documentation and DAT 11880 are preserved separately.
- **PRESERVED** — IBM/Norton brochure documents Windows 95/98.
- **ARTIFACT_WANTED** — versioned final installers and definition cut-offs for
  Symantec, F-PROT, Sophos, AVP/Kaspersky, ESET, Dr.Web, Avast, AVG, Avira,
  Bitdefender, Trend, Norman and VET.

## Windows NT

- **PRESERVED** — McAfee VirusScan 4.5.1 and SuperDAT documentation for NT4;
  DAT 11880 is preserved without claiming universal NT4 compatibility.
- **PRESERVED** — IBM/Norton brochure documents NT4 and Notes Server on NT3.51
  SP5/NT4 SP3.
- **ARTIFACT_WANTED** — original NT3.51/NT4 scanner media and final compatible
  definitions for the listed workstation/server vendors.

## Windows 2000

- **PRESERVED** — McAfee VirusScan 4.5.1 documentation, SuperDAT documentation,
  and DAT 11880 candidate definitions.
- **DOCUMENTED_ONLY** — primary IBM BigFix compatibility data shows multiple
  later enterprise AV families on Windows 2000, but it is not installer or
  final-definition evidence.
- **ARTIFACT_WANTED** — final ESET, Avast, AVG, Avira, Bitdefender, Kaspersky,
  Dr.Web, Symantec, Sophos, Trend, F-PROT and Norman Windows 2000 releases.

## Windows XP/Vista

- **PRESERVED** — existing Avast/AVG 18.8 installers, utilities, documentation,
  and Avast v18 VPS remain unchanged.
- **PRESERVED** — Bitdefender XP/Vista 2017 manual.
- **DEAD_SOURCE** — Bitdefender 2010 x86 `weekly.exe` official HTTP endpoint.
- **ARTIFACT_WANTED** — Bitdefender XP/Vista 2017 installer/weekly package and
  exact final XP/Vista releases for ESET, Avira, Kaspersky, Dr.Web, McAfee,
  Sophos, Trend, F-PROT and Norman.

## OS/2

- **PRESERVED** — IBM official service-level index identifies IBM AntiVirus 2.3
  and 2.4 update families `AV23x` and `AV24x`.
- **PRESERVED** — IBM-hosted Norton evidence documents native OS/2 support.
- **PRESERVED** — Doctor Web official DOS/OS2 product lineage page.
- **ARTIFACT_WANTED** — IBM AntiVirus milestones 1.02–1.06, 2.0–2.5 and 3.0;
  McAfee VirusScan 4.0.2/4.0.4; Dr Solomon 7.74; Norton 5.02/5.03.69; final
  F-PROT Professional; and a versioned Dr.Web OS/2 package with compatible VDB.
  IBM current downloads are entitlement-oriented; no login/account was used.

## Historical Linux

- **PRESERVED (deep pass)** — Comodo Antivirus for Linux 1.1.268025.1 x86-64
  RPM and i386/amd64 DEBs. The i386 RPM is now **DEAD_SOURCE** (404) but has an
  official exact size/MD5/SHA-1 fingerprint.
- **ARTIFACT_WANTED (deep pass)** — genuine Sophos SAV Linux 9.17.4
  `sav-linux-9-i386.tgz`; the official URL now returns an export-compliance
  interstitial. It was not bypassed or represented as installer bytes.
- **PRESERVED (deep pass)** — primary Linux/Unix evidence for Sophos 7.6.7 and
  9.17.x, McAfee VirusScan UNIX 4.32.0, ESET Linux Desktop, AVG 2011 and
  Bitdefender Scanner for Unices. See `historical-linux-unix-deep-pass.md`.

- **PRESERVED** — Dr.Web for UNIX File Servers 6.02 manual, including historical
  32/64-bit Linux distributions, VDB storage, engine layout and `update.pl`.
- **PRESERVED** — Trend Micro IWSVA 6.5 SP1 manual from the earlier pass.
- **DEAD_SOURCE** — Trend Micro ServerProtect Linux 2.5 guide URL loops through
  HTTP 301 responses; TLS verification was not bypassed.
- **DOCUMENTED_ONLY** — Dr.Web UNIX Server 10/11 manuals remain on official
  infrastructure; direct installers require download/licensing workflows.
- **ARTIFACT_WANTED** — Sophos SAV Linux 7.6.7, 9.16.x, 9.17.4/final 32-bit and
  matching IDE sets; F-PROT Linux final release/signatures; historical ESET,
  Bitdefender Scanner for Unices, AVG, Avast, Avira, McAfee UNIX, Kaspersky,
  Trend ServerProtect, Norman and Comodo packages.

## Current Linux

| Engine | Findings | Recommendation |
|---|---|---|
| ClamAV | Local CLI/daemon, offline CVD database snapshots, broad distro availability; x86-64/ARM64 builds | `FREE_ENABLE` |
| ESET Endpoint AV Linux | x86-64 distribution script, terminal operation, license/offline-license support; Internet needed for initial download | `TRIAL_QUALIFY`, `LICENSE_REVIEW` |
| Dr.Web Linux | Local scanner exists; commercial key/trial workflow and vendor updates | `TRIAL_QUALIFY`, `LICENSE_REVIEW` |
| Sophos Protection Linux 2026.2 | Central-managed; local `avscanner`; x86-64/ARM64; Debian 11–13 and major enterprise distros | `TRIAL_QUALIFY`; reject if Central dependency is unacceptable |
| Kaspersky Endpoint Security Linux 12.2 | CLI, x86/i386/x86-64/ARM64 packaging; documented removable-media/local-folder offline update | `TRIAL_QUALIFY`, `LICENSE_REVIEW` |
| Trend ServerProtect Linux | Local manual CLI scan and engine/pattern update; commercial activation and service components | `TRIAL_QUALIFY`, `PRESERVE_NOW` for legacy pattern evidence |
| Avast Business Linux | Business-managed product; historical versus current lineage unresolved | `NEEDS_RESEARCH`, `LICENSE_REVIEW` |
| Bitdefender Linux | Product/licensing varies between endpoint/server/SDK offerings | `NEEDS_RESEARCH`, `LICENSE_REVIEW` |
| Trellix/McAfee Linux | Enterprise licensing/update compatibility requires qualification | `TRIAL_QUALIFY`, `LICENSE_REVIEW` |

Exact Norwegian/EU prices were not stable or consistently published without
sales/account flows; they remain `unknown` and must be re-quoted during license
qualification rather than guessed.

## Current Windows

| Engine | Preservation-oriented finding | Recommendation |
|---|---|---|
| Microsoft Defender | Built-in, local `MpCmdRun` CLI/on-demand scan, intelligence update and offline scan; Windows x64/ARM64 follows OS support | `FREE_ENABLE` |
| ClamAV | Open-source local CLI; Windows win32/x64 packages; snapshot-friendly databases | `FREE_ENABLE` |
| Avast Free | Free personal use, Windows 7–11, x86/x64 and Windows 11 ARM; Internet-backed updates; GUI-centric | `LICENSE_REVIEW` |
| AVG Free | Explicit personal/family use, Windows 7–11 x86/x64; no ARM; custom/on-demand scans; Internet updates | `LICENSE_REVIEW` |
| Avira Free | Windows 7–11, x86/x64 and Windows 11 ARM; free tier; cloud/update dependence | `LICENSE_REVIEW` |
| Bitdefender Free | On-demand/system scans and online management/update model; no stable automation contract established | `TRIAL_QUALIFY` |
| ESET | Local `ecls.exe` on-demand CLI with action switches; commercial/trial licensing | `BUY_CANDIDATE`, `TRIAL_QUALIFY` |
| Dr.Web | Commercial/trial, local scanner family; exact unattended scan-only license terms unresolved | `TRIAL_QUALIFY`, `LICENSE_REVIEW` |
| Kaspersky | Local scanner/offline-update workflows exist; regional/legal availability and license terms require review | `LICENSE_REVIEW` |
| Norton, F-Secure | Consumer GUI/cloud services; no supported stable AVBox CLI identified | `REJECT_FOR_AVBOX` pending contrary evidence |
| Sophos | Current endpoint is Central/business oriented | `REJECT_FOR_AVBOX` for private simplicity; `TRIAL_QUALIFY` only if licensing fits |
| Trend Micro, McAfee/Trellix | Consumer/enterprise offerings; stable personal local CLI contract not established | `LICENSE_REVIEW` |

No purchases, accounts, installers or trials were initiated. Prices remain
`unknown` where an official Norwegian/EU checkout-independent quote was absent.

## Open-source detectors

- **DOCUMENTED_ONLY** — ClamAV current stable 1.5.4 and LTS 1.4.6 authoritative
  release metadata; classified `antivirus_engine`.
- **DOCUMENTED_ONLY** — YARA 4.5.5 and YARA-X 1.19.0 release metadata;
  classified `rule_engine`.
- **DOCUMENTED_ONLY** — LOKI authoritative repository/releases;
  classified `ioc_detector`.
- **DOCUMENTED_ONLY** — Linux Malware Detect authoritative repository/releases;
  classified `malware_detector`.
- **DOCUMENTED_ONLY** — chkrootkit upstream site; classified `system_detector`.
- **DOCUMENTED_ONLY** — rkhunter SourceForge release archive; classified
  `system_detector`.
- A machine-readable future RAB timeline plan is preserved as
  `manifests/rab-future-acquisition.yaml`. Commercial rescue artifacts took
  precedence over reproducible source archives in this pass.

## Artifact wanted list

The machine-readable wanted list records exact known version identities and
known missing filenames without fabricated URLs. Highest priorities are a live
4.x XDAT/SuperDAT, OS/2 product media, final F-PROT packages/signatures, Sophos
SAV Linux 9.17.4 plus IDEs, and Bitdefender XP/Vista 2017 installer/updates.

## Dead endpoints

- Trellix `11872xdat.exe` — HTTP 404.
- Trellix `avvdat-11878.tar` — HTTP 404 after directory rotation.
- Bitdefender 2010 x86 `weekly.exe` — HTTP 404.
- Avira FuseBundle — vendor states it is no longer offered.

## Fragile endpoints

- Trellix 4.x and NAI DAT directories: live indexes and backing objects rotate
  independently.
- Avast `go.avast.com` Vista redirector: preserved TLS hostname mismatch.
- Trend Micro ServerProtect 2.5 PDF: redirect loop.

## Mutable endpoints

- Avast and AVG XP/Vista installer current-object URLs.
- Avast `vps18/vpsupd.exe`.
- Trellix 4.x DAT directory and mutable readme.

## RAB export readiness

Schema 2 records immutable bytes and all four digests, size, HTTP/redirect
metadata, acquisition/failure events, separate product/engine/definition
versions, platform/architecture/compatibility, risks, relationships,
provenance, and rights. Identical RAB bytes can retain AVBox events as additional
provenance. `verify-rab-export` validates exported bytes and required metadata.
The preservation volume remains separate from the disposable OS disk.
