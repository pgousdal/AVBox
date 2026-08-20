# Scanner adapters

Every runtime implements `probe`, `capabilities`, `prepare`, `scan`, `normalize`, and `cleanup`. Application services do not know whether it uses a local CLI, daemon/socket, VM, emulator or API.

Capabilities cover file, directory, archive, disk-image, boot-sector, memory and system scans plus scan-only/repair/delete/quarantine actions. Dependency mode distinguishes local, cloud-assisted and cloud-required engines. Registry evidence independently records offline-definition and snapshot support.

No adapter implementation or engine is installed in M0.

