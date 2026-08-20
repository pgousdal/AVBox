# AVBox Bootstrap Time-Critical Status

Generated: 2026-08-20 UTC

This is a factual preservation status report for temporary staging. Public
download availability does not establish redistribution rights. RAB remains the
intended long-term preservation authority.

## Secured before this pass

- Avast Free Antivirus 18.8 XP/Vista offline installer.
- Avast XP/Vista uninstall utility.
- AVG Internet Security/AntiVirus 18.8 XP/Vista offline installer.
- AVG XP/Vista uninstall utility.
- Avast version-18 `vpsupd.exe` offline definitions package.
- Avast and AVG XP/Vista compatibility documentation.
- AVG uninstall-tool documentation.

## BLAKE3 backfill

Debian `b3sum` 1.8.1-2 from Debian 13 `trixie/main` is installed. All eight
pre-existing artifacts received BLAKE3 values in the append-only
`logs/integrity.jsonl` overlay. Historical acquisition events were not rewritten.
New acquisitions record BLAKE3 at ingest time.

## Mutable and fragile sources

- `https://install.avcdn.net/iavs9x-xp/avast_free_antivirus_setup_offline.exe`
  — mutable current-object installer.
- `https://install.avcdn.net/avg/iavs9x-xp/avg_internet_security_setup_offline.exe`
  — mutable current-object installer.
- `https://install.avcdn.net/vps18/vpsupd.exe` — mutable current-object Avast
  version-18 definitions.
- `https://downloadcenter.trellix.com/products/datfiles/4.x/nai/readme.txt`
  — mutable metadata for a still-living legacy 4.x DAT directory.
- `https://downloadcenter.trellix.com/products/datfiles/4.x/nai/11872xdat.exe`
  — fragile: listed by the official index during discovery but returned HTTP 404
  during acquisition.
- `http://download.bitdefender.com/updates/bitdefender_2010/x86/weekly.exe`
  — dead/fragile mutable endpoint; currently HTTP 404 and lacks authenticated
  transport.
- `https://go.avast.com/windows-vista-antivirus` — fragile; prior acquisition
  failed enforced TLS hostname validation. That failure remains preserved.

`acquire --refresh-mutable` downloads mutable sources to temporary files,
hashes before commit, deduplicates identical SHA-256 bytes while appending a new
event, and keeps changed bytes as a new immutable object. No schedule is enabled.

## AVG 18.8 definition status

Status: **WANTED**.

Official AVG evidence says products from 2017 onward do not support importing
offline definition files, and “manual” update means user-initiated online update:

- https://community.avg.com/t/how-do-i-install-the-definitions-update-bin-file/255179
- https://community.avg.com/t/offline-updates/213300
- https://support.avg.com/SupportArticleView?l=en&urlname=Update-AVG-Antivirus
- https://support.avg.com/SupportArticleView?l=en&urlName=AVG-Windows-XP-Vista-support-FAQ

No distinct official AVG 18.8 offline definition package or verified legacy
endpoint was found. Compatibility of Avast `vps18/vpsupd.exe` with AVG 18.8 is
explicitly unverified and must not be assumed.

## Newly secured

- AVG staff evidence that offline-file updates ended for 2017 and later.
- McAfee/Trellix 4.x DAT endpoint `readme.txt` (a refresh produced identical
  SHA-256 and correctly appended provenance without duplicate bytes).
- McAfee SuperDAT 1.2 User's Guide, documenting DOS, Windows 3.1, Windows
  95/98/NT/2000 and XDAT compatibility with McAfee 4.x.x and later.
- McAfee VirusScan 4.5.1 Release Guide, documenting Windows 95/98/NT4/2000/ME
  and DAT mirroring/update behavior.
- Bitdefender Security for XP & Vista 2017 user guide, documenting `weekly.exe`
  manual updates.
- Avira official evidence that the VDF FuseBundle manual-update file is no
  longer offered.
- Trend Micro IWSVA 6.5 SP1 guide, documenting ActiveUpdate and manual pattern
  packages.

## Failed official acquisitions

- Trellix/McAfee `11872xdat.exe`: HTTP 404 after being listed by the official
  directory. The rapid listing/download inconsistency makes this especially
  time-critical.
- Bitdefender 2010 x86 `weekly.exe`: HTTP 404.
- Avast Vista redirector page: historical TLS certificate hostname mismatch;
  validation was not disabled.

Failure events retain requested URL, UTC time, DNS results, HTTP status, error,
redirect information, TLS-validation state, partial byte count, and source risk
where the schema-v2 downloader made the attempt.

## Targeted discovery findings

- **Trellix/McAfee:** living official 4.x XDAT and V3 DAT indexes plus extensive
  NT4/2000-era manuals. The 4.x binary directory should be retried promptly only
  after resolving a currently downloadable link from the live official index.
- **Trend Micro:** official historical manuals and current pattern-download
  documentation survive. Resolve the exact current OPR download target before
  acquisition; do not infer a filename from the documented naming convention.
- **Bitdefender:** XP/Vista manuals survive, but the documented Bitdefender 2010
  cumulative-update endpoint is gone. Rescue-CD directories deserve a later
  exact-link audit.
- **Avira:** official support confirms the old FuseBundle endpoint is dead and
  manual update files are no longer offered.
- **ESET/NOD32:** official older-version download workflows exist, but no exact
  XP-version installer or definition endpoint was validated in this pass.
- **Kaspersky:** official documentation describes offline/copy-update workflows,
  but no public legacy XP package with sufficiently clear product compatibility
  was selected.
- **Dr.Web:** official historical versioned documentation remains online;
  current CureIt is not an XP preservation target without version-specific
  compatibility evidence.
- **Sophos, F-PROT/FRISK, Norman:** no sufficiently evidenced, living public
  legacy artifact endpoint was identified in this targeted pass. No mirror was
  substituted.

## Acquire soon

1. A currently downloadable McAfee/Trellix 4.x XDAT directly linked by the live
   official index, because entries rotate and one vanished during this pass.
2. Exact Trend Micro OPR pattern and compatible legacy scan-engine targets after
   resolving them through the official download center.
3. Any still-live Bitdefender XP/Vista `weekly.exe` version discovered through an
   official page rather than inferred paths.
4. Exact ESET XP-compatible older-version installer and update evidence if the
   official version selector still exposes them.

## Can wait for later RAB ingestion

Stable, versioned vendor manuals already secured can wait. Mutable installers,
definition endpoints, rotating DAT indexes, and failed/fragile sources should be
handled before broader historical documentation mirroring.

## Preserve-before-M0 rescue update — 2026-08-20

- **PRESERVED:** McAfee/Trellix AVV DAT 11880 (`avvdat-11880.tar`), dated
  2026-08-19, plus the exact live mutable directory response.
- **PRESERVED:** McAfee/Trellix XDAT 11880 (`11880xdat.exe`), dated 2026-08-19,
  plus the exact live NAI directory response; the executable was never run.
- **DEAD_SOURCE:** DAT 11878 returned HTTP 404 after the directory rotated from
  11877/11878 to 11879/11880; the earlier XDAT 11872 failure remains recorded.
- **PRESERVED:** IBM-hosted Norton DOS/Win16/Win9x/NT/OS2 compatibility
  brochure and IBM AntiVirus OS/2 2.3/2.4 service-level evidence.
- **PRESERVED:** Doctor Web DOS/OS2 product evidence and UNIX File Server 6.02
  historical Linux/update documentation.
- **DEAD_SOURCE:** Trend Micro ServerProtect Linux 2.5 guide entered an HTTP
  301 redirect loop; no redirect or TLS control was weakened.
- Detailed platform surveys, current-engine qualification, wanted identities,
  and the future open-source RAB timeline are in `preserve-before-m0.md` and
  `rab-future-acquisition.yaml`.
