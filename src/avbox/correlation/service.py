from __future__ import annotations

import time
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import cast

from avbox.models import (
    CorrelationResult,
    CorrelationState,
    ExactCorrelation,
    ExactLookupState,
    Hashes,
    InputArtifact,
    ObjectIdentity,
    PreservationContext,
    ScanJob,
)

from .providers import RabCorrelationProvider


class CorrelationService:
    def __init__(
        self,
        provider: RabCorrelationProvider,
        *,
        max_objects: int = 1000,
        max_similarity_queries: int = 100,
        total_deadline_seconds: float = 30.0,
    ):
        self.provider = provider
        self.max_objects = max_objects
        self.max_similarity_queries = max_similarity_queries
        self.total_deadline_seconds = total_deadline_seconds

    def process(self, job: ScanJob) -> None:
        started = time.monotonic()
        objects: list[tuple[InputArtifact, Sequence[object], PreservationContext]] = [
            (job.input_artifact, job.analyzer_results, job.preservation_context)
        ]
        objects.extend(
            (converted, child.analyzer_results, child.preservation_context)
            for child in job.derived_objects
            if (converted := self._artifact(child.object)) is not None
        )
        similarity_used = 0
        for index, (artifact, analyzers, context) in enumerate(objects):
            if index >= self.max_objects:
                context.rab_correlation = "AVAILABLE"
                context.correlation = self._skipped("max_correlated_objects_per_job exhausted")
                continue
            if time.monotonic() - started >= self.total_deadline_seconds:
                context.rab_correlation = "AVAILABLE"
                context.correlation = self._skipped("total_correlation_deadline exhausted")
                continue
            fingerprint = self._ssdeep(analyzers)
            if fingerprint and similarity_used >= self.max_similarity_queries:
                fingerprint = None
            elif fingerprint:
                similarity_used += 1
            result = self.provider.correlate(artifact, fingerprint)
            context.rab_correlation = (
                "NOT_AVAILABLE" if result.state == CorrelationState.UNAVAILABLE else "AVAILABLE"
            )
            context.correlation = result

    def _skipped(self, reason: str) -> CorrelationResult:
        return CorrelationResult(
            provider_id=self.provider.provider_id,
            provider_version=self.provider.provider_version,
            state=CorrelationState.PARTIAL,
            exact=ExactCorrelation(
                state=ExactLookupState.ERROR, completeness=CorrelationState.PARTIAL
            ),
            skipped_reason=reason,
        )

    @staticmethod
    def _ssdeep(analyzers: Sequence[object]) -> str | None:
        for analyzer in analyzers:
            for observation in getattr(analyzer, "observations", []):
                if observation.observation_type == "similarity.ssdeep":
                    value = observation.value
                    if isinstance(value, dict) and isinstance(value.get("fingerprint"), str):
                        return cast(str, value["fingerprint"])
        return None

    @staticmethod
    def _artifact(value: object) -> InputArtifact | None:
        if isinstance(value, InputArtifact):
            return value
        if not isinstance(value, ObjectIdentity):
            return None
        if not value.blake3 or not value.sha1 or not value.md5:
            return None
        return InputArtifact(
            hashes=Hashes(
                sha256=value.sha256,
                blake3=value.blake3,
                sha1=value.sha1,
                md5=value.md5,
            ),
            byte_size=value.size,
            filename=value.filename or "derived-object",
            media_type=value.media_type or "application/octet-stream",
            source="avbox-derived-object",
            submitted_at=datetime.now(UTC),
        )
