from __future__ import annotations

from avbox.config import AppSettings

from .adapters import (
    ClamAVAdapter,
    LokiAdapter,
    MaldetAdapter,
    RootkitAdapter,
    YaraAdapter,
    YaraXAdapter,
)
from .base import ScannerAdapter, SystemDetectorAdapter


def build_adapters(
    settings: AppSettings,
) -> tuple[dict[str, ScannerAdapter], dict[str, SystemDetectorAdapter]]:
    raw_output = settings.paths.raw_output
    timeout = settings.runtime.default_timeout_seconds
    memory = settings.runtime.memory_limit_mib
    use_bwrap = settings.runtime.use_bubblewrap
    rules = settings.paths.rules / "avbox-m1.yar"
    files: list[ScannerAdapter] = [
        ClamAVAdapter(
            raw_output_root=raw_output, timeout=timeout, memory_mib=memory, use_bwrap=use_bwrap
        ),
        YaraAdapter(
            raw_output_root=raw_output,
            timeout=timeout,
            rules=rules,
            memory_mib=memory,
            use_bwrap=use_bwrap,
        ),
        YaraXAdapter(
            raw_output_root=raw_output,
            timeout=timeout,
            rules=rules,
            memory_mib=memory,
            use_bwrap=use_bwrap,
        ),
        LokiAdapter(
            raw_output_root=raw_output, timeout=timeout, memory_mib=memory, use_bwrap=use_bwrap
        ),
        MaldetAdapter(
            raw_output_root=raw_output, timeout=timeout, memory_mib=memory, use_bwrap=use_bwrap
        ),
    ]
    systems: list[SystemDetectorAdapter] = [
        RootkitAdapter(
            "chkrootkit",
            "chkrootkit",
            settings.paths.raw_output,
            settings.runtime.default_timeout_seconds,
            memory,
        ),
        RootkitAdapter(
            "rkhunter",
            "rkhunter",
            settings.paths.raw_output,
            settings.runtime.default_timeout_seconds,
            memory,
        ),
    ]
    return ({item.scanner_id: item for item in files}, {item.scanner_id: item for item in systems})
