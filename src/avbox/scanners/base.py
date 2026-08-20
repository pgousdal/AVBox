from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from avbox.models import Capability, QualificationState, ScannerClass, ScannerResult, Verdict


@dataclass(frozen=True)
class ProbeResult:
    available: bool
    detail: str
    state: QualificationState = QualificationState.NOT_INSTALLED
    version: str | None = None
    definition_state: dict[str, str | int | None] | None = None


@dataclass(frozen=True)
class PreparedScan:
    job_id: str
    immutable_input: Path
    working_path: Path
    context: dict[str, Any]


class ScannerAdapter(ABC):
    """Replaceable boundary for CLI, daemon, VM, emulator, or API scanners."""

    @abstractmethod
    def probe(self) -> ProbeResult: ...

    @abstractmethod
    def capabilities(self) -> set[Capability]: ...

    @abstractmethod
    def prepare(
        self, *, job_id: str, immutable_input: Path, working_root: Path
    ) -> PreparedScan: ...

    @abstractmethod
    def scan(self, prepared: PreparedScan) -> object: ...

    @abstractmethod
    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]: ...

    @abstractmethod
    def cleanup(self, prepared: PreparedScan) -> None: ...

    def run_prepared(self, prepared: PreparedScan) -> tuple[Verdict, ScannerResult]:
        return self.normalize(self.scan(prepared))

    @property
    @abstractmethod
    def scanner_id(self) -> str: ...

    @property
    @abstractmethod
    def scanner_class(self) -> ScannerClass: ...

    @property
    def supports_file_scan(self) -> bool:
        return Capability.FILE_SCAN in self.capabilities()

    def update(self) -> object:
        raise NotImplementedError(f"{self.scanner_id} update is not implemented")


class SystemDetectorAdapter(ABC):
    """Contract for host inspection tools that do not scan submitted files."""

    @property
    @abstractmethod
    def scanner_id(self) -> str: ...

    @property
    def scanner_class(self) -> ScannerClass:
        return ScannerClass.SYSTEM_DETECTOR

    @abstractmethod
    def probe(self) -> ProbeResult: ...

    @abstractmethod
    def system_scan(self) -> object: ...

    @abstractmethod
    def normalize(self, native_result: object) -> tuple[Verdict, ScannerResult]: ...

    def update(self) -> object:
        raise NotImplementedError(f"{self.scanner_id} update is not implemented")
