from __future__ import annotations

from enum import StrEnum


class ScannerClass(StrEnum):
    ANTIVIRUS_ENGINE = "antivirus_engine"
    RULE_ENGINE = "rule_engine"
    IOC_DETECTOR = "ioc_detector"
    MALWARE_DETECTOR = "malware_detector"
    SYSTEM_DETECTOR = "system_detector"


class HistoricalMode(StrEnum):
    PERIOD_CORRECT = "PERIOD_CORRECT"
    FINAL_HISTORICAL = "FINAL_HISTORICAL"
    MAXIMUM_RETRO = "MAXIMUM_RETRO"


class Verdict(StrEnum):
    CLEAN = "CLEAN"
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    PUA = "PUA"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_SCANNED = "NOT_SCANNED"
    UNKNOWN = "UNKNOWN"


class ScanPolicy(StrEnum):
    READ_ONLY = "READ_ONLY"
    REPAIR_COPY = "REPAIR_COPY"


class RightsStatus(StrEnum):
    ALLOWED = "allowed"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class Capability(StrEnum):
    FILE_SCAN = "file_scan"
    DIRECTORY_SCAN = "directory_scan"
    ARCHIVE_SCAN = "archive_scan"
    DISK_IMAGE_SCAN = "disk_image_scan"
    BOOT_SECTOR_SCAN = "boot_sector_scan"
    MEMORY_SCAN = "memory_scan"
    SYSTEM_SCAN = "system_scan"
    SCAN_ONLY = "scan_only"
    REPAIR = "repair"
    DELETE = "delete"
    QUARANTINE = "quarantine"


class DependencyMode(StrEnum):
    LOCAL_ENGINE = "local_engine"
    CLOUD_ASSISTED = "cloud_assisted"
    CLOUD_REQUIRED = "cloud_required"


class QualificationState(StrEnum):
    NOT_INSTALLED = "NOT_INSTALLED"
    INSTALLED = "INSTALLED"
    PROBED = "PROBED"
    QUALIFIED = "QUALIFIED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    DISABLED = "DISABLED"


class FindingKind(StrEnum):
    SIGNATURE_MATCH = "signature_match"
    IOC_MATCH = "ioc_match"
    RULE_MATCH = "rule_match"
    HEURISTIC_WARNING = "heuristic_warning"
    INTEGRITY_WARNING = "integrity_warning"
    ROOTKIT_WARNING = "rootkit_warning"
    OPERATIONAL_ERROR = "operational_error"
