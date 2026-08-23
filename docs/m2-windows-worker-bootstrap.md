# M2.0 Windows qualification worker bootstrap

## Scope and outcome

This milestone creates the infrastructure prerequisite for M2. It does not
implement an AVBox Windows worker protocol or integrate a Windows scanner into
analysis jobs.

The dedicated qualification guest is `avbox-m2-windows-current` (UUID
`d21e48bf-33cc-4bef-86a1-8820b7dd57a5`). It is a disposable Windows 11
Enterprise Evaluation VM for current Microsoft Defender Antivirus work only.
It is not preservation storage, a malware execution sandbox, or a general
Windows service.

## Media and licensing provenance

Windows was acquired on 2026-08-23 from the official [Microsoft Evaluation
Center](https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise).
The English (United States), x64 Windows 11 Enterprise 25H2 link resolved via
Microsoft's `https://aka.ms/Win11E-ISO-25H2-en-us` redirect to
`software-static.download.prss.microsoft.com`.

The downloaded image was
`26200.6584.250915-1905.25h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso`,
7,092,807,680 bytes. Its SHA-256 was:

```text
a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9
```

That value exactly matched Microsoft's current `Enterprise Eval x64 Eval
EN-US DVD9` value in the official hash document reached through
`https://aka.ms/Win11-Hash-PDF`. The ISO was ejected and deleted after
installation to reclaim host space; it is not in Git.

No product key was supplied and no activation control was bypassed. Windows
reports `Windows(R), EnterpriseEval edition`, `TIMEBASED_EVAL channel`, license
status `1` (licensed), and 129,533 minutes of grace remaining at final
collection time. The Microsoft evaluation media describes this as a 90-day
evaluation.

The only additional installation media was Fedora's official stable
`virtio-win-0.1.285.iso`, obtained from
`https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso`.
It supplied the QEMU guest agent and virtio-serial driver. It was ejected and
deleted after installation.

## VM configuration

| Property | Qualified value |
| --- | --- |
| Name | `avbox-m2-windows-current` |
| OS | Microsoft Windows 11 Enterprise Evaluation, 25H2 |
| Version/build | `10.0.26200`, build `26200.6584` |
| Architecture | 64-bit x86 |
| Installation time | `2026-08-23T01:02:34Z` |
| vCPU | 2, host-passthrough |
| RAM | 4 GiB |
| Disk | 64 GiB sparse qcow2, SATA |
| Machine | Q35/KVM |
| Firmware | UEFI pflash, `/usr/share/OVMF/OVMF_CODE_4M.ms.fd` |
| Secure Boot | enabled and confirmed by Windows |
| TPM | emulated CRB TPM 2.0; present, ready, enabled and activated |
| Network | existing libvirt `default` NAT, e1000e, MAC `52:54:00:89:a2:20` |
| Scan baseline link | persistently down |
| Console | SPICE bound to host loopback only |
| Autostart | disabled |

The VM booted after installation, after the driver restart, and from the
snapshot-backed disk. The host-only QEMU guest-agent channel recovered after
each completed boot. No nested virtualization is configured.

## Windows and Defender baseline

Final observed Defender state after the explicit update operation:

| Field | Value |
| --- | --- |
| Product/platform | `4.18.26070.9` |
| Engine | `1.1.26070.7` |
| Security intelligence | `1.457.297.0` |
| Intelligence timestamp | `2026-08-22T20:16:37Z` |
| Antivirus | enabled |
| Real-time protection | enabled |
| Tamper protection | enabled |
| PUA protection | enabled (`2`) |
| `WinDefend` service | running, automatic |

The current executable was discovered by enumerating the versioned platform
directory, not by assuming a version:

```text
C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MpCmdRun.exe
File version: 4.18.26070.9 (797b3603749206dfffe67a1cc891531b0a2cf438)
```

Microsoft documents the versioned platform directory as the preferred current
location and `C:\Program Files\Windows Defender` as the inbox fallback in its
[MpCmdRun reference](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus).

The image initially contained platform `4.18.23110.3`, engine `1.1.23110.2`,
and intelligence `1.403.7.0` dated 2023-12-05. A PowerShell update attempt was
slow and ended around a Windows shutdown without advancing versions. After a
reliable restart, the bounded explicit operation
`MpCmdRun.exe -SignatureUpdate -MMPC` exited successfully and advanced all
three version families to the values above. Update is therefore an explicit
operation, never an implicit scan prerequisite.

## Privacy and network planes

The Microsoft media defaulted to advanced MAPS (`MAPSReporting=2`) and safe
sample submission (`SubmitSamplesConsent=1`). The qualification baseline is:

```text
MAPSReporting=0                 # Disabled
SubmitSamplesConsent=2         # Never Send
DisableBlockAtFirstSeen=true
RealTimeProtectionEnabled=true
IsTamperProtected=true
```

Microsoft documents `SubmitSamplesConsent=2` as Never Send in
[`Set-MpPreference`](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference),
and explains that disabling sample submission also disables block-at-first-
sight file analysis in its [cloud/sample-submission
documentation](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).
Microsoft notes that detection metadata can still be sent when cloud
protection is enabled; the M2.0 baseline therefore disables MAPS as well as
automatic sample submission. These settings were rechecked after reboot.

The demonstrated operating model is:

* **Update mode:** explicitly raise the configured NAT NIC link, run the
  selected Defender update operation, record before/after provenance, then
  lower the link.
* **Scan mode:** NIC link down in both runtime and persistent libvirt
  configuration. Windows reported the adapter disconnected, 0 bps, and an
  HTTPS connectivity check returned false. Local custom scans still worked.

The persistent baseline is scan mode. A future worker must fail closed if the
link cannot be confirmed down. It must not interpret `Never Send` alone as
proof that no metadata can leave the machine.

WinRM, Remote Desktop (`TermService`), and SMB server (`LanmanServer`) are
stopped and disabled. No host port forward was added. SPICE listens only on
127.0.0.1. Windows Firewall remains enabled. The existing libvirt NAT network
was used without configuration changes.

## Harmless direct tests

Tests ran directly on Windows through the current versioned `MpCmdRun.exe`.
No submitted object was executed and no real malware was used.

The clean deterministic fixture was 54 bytes with SHA-256:

```text
597c3e02d950f8eccf621cb11e7dae80fa20887dfcc670412ba762ed73256276
```

With the NIC disconnected, this command completed successfully:

```text
MpCmdRun.exe -Scan -ScanType 3 -File C:\AVBox\staging\clean.txt -DisableRemediation
Scan starting...
Scan finished.
Scanning C:\AVBox\staging\clean.txt found no threats.
```

The harmless standard 68-byte EICAR fixture had expected SHA-256:

```text
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

It was created only as a disposable staged copy while the NIC was down.
Defender blocked reads, then recorded threat ID `2147519003` with native name
`Virus:DOS/EICAR_Test_File`, severity ID `5`, category ID `42`, and
`DidThreatExecute=false`. The staged file did not remain afterward.

This establishes recognition but also an important constraint: although
Microsoft documents `-DisableRemediation` for custom scans, real-time
protection can race with or supersede the custom scan and quarantine/remove
the disposable staged copy. Tamper protection prevented the attempted narrow
real-time pause. M2 must therefore treat the worker copy as disposable, retain
the immutable AVBox source outside Windows, verify identity before scanning,
capture detection evidence promptly, and clean any remaining staging bytes.
M2 must not claim that `-DisableRemediation` alone guarantees preservation of a
worker-side copy.

Both fixtures were removed and `C:\AVBox\staging` was empty at baseline.

## Management and staging boundary for M2

M2 should implement a small dedicated authenticated service, not expose QEMU
guest-agent execution, WinRM, RPC, SMB, RDP, or a general shell as its product
boundary. The recommended service should use mutually authenticated TLS with
an AVBox-pinned worker identity, an explicit protocol version, fixed server
configuration, bounded request/response sizes, bounded raw output, and no
caller-controlled endpoint, URL, or filesystem path.

The future controlled root is `C:\AVBox\staging`. Its ACL grants full control
only to `SYSTEM` and `BUILTIN\Administrators`, with inheritance removed. The
future sequence is:

1. AVBox generates a job/object identifier.
2. AVBox streams bytes into a generated worker-side path.
3. The worker verifies expected size and SHA-256 before scan.
4. The selected adapter scans the generated path without executing it.
5. The worker captures bounded native evidence and version provenance.
6. The worker removes staged bytes after success or failure.

The submitted filename is metadata only. It must never choose a privileged
path. No preservation object belongs in this VM.

The QEMU guest agent is bootstrap/qualification host control only. It is
transported over a host-owned virtio channel and has no network listener, but
it is a privileged general execution interface and therefore is not the M2
service boundary.

## Snapshot and lifecycle

The offline external disk snapshot is:

```text
m2-bootstrap-defender-20260823
```

It represents installed Windows 11 Enterprise Evaluation 25H2, current
Defender platform/engine/intelligence listed above, privacy policy applied,
management services disabled, installed QEMU guest-agent support, and empty
AVBox staging. It is a disk-only recovery/periodic-reset point, not a per-file
rollback mechanism. TPM and UEFI variable state are separate host-managed
state and are not claimed to be captured by the disk-only snapshot. Recovery
procedures must verify or restore the persistent NIC-down configuration before
booting the recovered guest.

Normal jobs should use per-job staging cleanup. Snapshot rollback is reserved
for recovery or periodic re-baselining unless later qualification shows that a
Defender or worker failure contaminates state in a way ordinary cleanup cannot
handle.

## Reproduction and host-integrity notes

The VM was created with `virt-install` using Q35, 2 vCPU, 4096 MiB RAM, a
64-GiB sparse SATA qcow2, e1000e on the existing `default` network, UEFI,
emulated TPM 2.0, a host-only guest-agent channel, and loopback-only SPICE.
Unattended setup material and VM media remained outside Git. The Windows ISO
hash must be rechecked against Microsoft's then-current published hash before
any rebuild; mutable current versions must not be assumed reproducible.

At the start, unrelated guest-definition hashes were recorded. At final check,
the hashes for `avbox-bootstrap`, `avbox-m1-qualification`,
`ubb-debian13-qualification`, and the `default` network matched exactly.
`debian13-base` and `debian13-dev` were present initially but disappeared from
libvirt during the run. No issued task command targeted, destroyed, undefined,
or modified either domain. They were not recreated because doing so would
modify unrelated infrastructure. This concurrent external-state change must
be considered when auditing host-wide inventory, but it did not change the
M2.0 guest or default network configuration.

Final state: the VM is shut off, autostart is disabled, all virtual CD drives
are empty, its persistent NIC link is down, staging is empty, and no ISO,
qcow2, credential, product key, EICAR bytes, or snapshot is stored in Git.
