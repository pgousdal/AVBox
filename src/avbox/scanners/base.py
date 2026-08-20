from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from avbox.models import Capability, ScannerResult, Verdict


@dataclass(frozen=True)
class ProbeResult:
    available: bool
    detail: str


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
