# Roadmap

- **M0:** foundation.
- **M1:** current Linux worker (implemented/qualified per `m1-acceptance.md`). These span antivirus, rule, IOC, malware and system/rootkit classes, not seven antivirus engines.
- **M1.1:** RAB Protocol v1 and generic asynchronous analysis-job foundation.
- **M1.2:** exact identity, safe filename/extension metadata, and bounded libmagic file-type evidence.
- **M1.3:** generic static characteristics: bounded strings, Shannon entropy/byte statistics, isolated ExifTool metadata, and ssdeep similarity groundwork (TLSH deferred pending trusted Debian packaging).
- **M1.4:** bounded userspace container and recursive object analysis (ZIP/tar/gzip/bzip2/xz).
- **M1.4a:** LHA/LZX and safe userspace ISO/container extensions.
- **M1.4b:** selected disk-image child enumeration.
- **M1.4c:** MBR primary and Amiga RDB/HDF traversal into qualified filesystems
  (implemented; EBR, GPT, and flat HDF deferred).
- **M1.5:** bounded PE/ELF/DOS MZ/Amiga HUNK structural analysis
  (implemented; Mach-O and NE/LE/LX qualification deferred).
- **M1.6:** document analysis (PDF/OLE/OOXML/RTF and embedded structures).
- **M1.7:** retro/media validators.
- **M2:** Windows worker: Defender and ClamAV first; qualify Avast/AVG/Avira/Bitdefender Free and commercial ESET/Dr.Web later.
- **M3:** safe submission and durable reports.
- **M4:** Amiga historical worker.
- **M5:** DOS historical worker.
- **M6:** Atari historical worker.
- **M7:** OS/2 and old Windows.
- **M8+:** Apple II/IIGS, Classic Mac, RISC OS, MSX, PC-98 and other qualified platforms.

Safety and preservation evidence may justify splitting or reordering milestones.
