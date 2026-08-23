from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from avbox.analyzers import GenericAnalyzer, build_generic_analyzers
from avbox.analyzers.containers import ContainerAnalyzer
from avbox.application import JobService, ScanService
from avbox.config import AppSettings
from avbox.correlation import (
    CorrelationService,
    HTTPRabCorrelationProvider,
    UnavailableRabCorrelationProvider,
)
from avbox.preservation import PreservationService
from avbox.protocol import RABService
from avbox.registry import RegistryService
from avbox.scanners.base import ScannerAdapter, SystemDetectorAdapter
from avbox.scanners.factory import build_adapters


@dataclass
class Context:
    settings: AppSettings
    registry: RegistryService
    jobs: JobService
    adapters: dict[str, ScannerAdapter] = field(default_factory=dict)
    system_adapters: dict[str, SystemDetectorAdapter] = field(default_factory=dict)
    scans: ScanService | None = None
    rab_protocol: RABService | None = None
    generic_analyzers: dict[str, GenericAnalyzer] = field(default_factory=dict)


def build_context(config_path: Path | None = None) -> Context:
    selected = config_path or Path(os.environ.get("AVBOX_CONFIG", "config/avbox.yaml"))
    settings = AppSettings.from_yaml(selected)
    registry = RegistryService(settings.paths.registry)
    jobs = JobService(settings.storage.sqlite_path)
    adapters, system_adapters = build_adapters(settings)
    generic_analyzers = build_generic_analyzers(settings)
    scans = ScanService(
        jobs=jobs,
        adapters=adapters,
        system_adapters=system_adapters,
        generic_analyzers=generic_analyzers,
        staging=settings.paths.staging,
        quarantine=PreservationService(settings.paths.quarantine),
        maximum_file_bytes=settings.runtime.maximum_file_bytes,
    )
    scans.recursive_analyzer = ContainerAnalyzer(settings, scans)
    correlation_provider = (
        HTTPRabCorrelationProvider(settings.rab_correlation)
        if settings.rab_correlation.enabled
        else UnavailableRabCorrelationProvider()
    )
    scans.correlation_service = CorrelationService(
        correlation_provider,
        max_objects=settings.rab_correlation.max_correlated_objects_per_job,
        max_similarity_queries=settings.rab_correlation.max_similarity_queries_per_job,
        total_deadline_seconds=settings.rab_correlation.total_deadline_seconds,
    )
    rab_protocol = RABService(
        settings=settings.rab_protocol,
        jobs=jobs,
        scans=scans,
        raw_output_root=settings.paths.raw_output,
    )
    return Context(
        settings=settings,
        registry=registry,
        jobs=jobs,
        adapters=adapters,
        system_adapters=system_adapters,
        scans=scans,
        rab_protocol=rab_protocol,
        generic_analyzers=generic_analyzers,
    )
