from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

import httpx
from pydantic import ValidationError

from avbox.config import RABCorrelationSettings
from avbox.models import (
    CorrelationErrorCode,
    CorrelationResult,
    CorrelationState,
    ExactCorrelation,
    ExactLookupState,
    ExactMatch,
    InputArtifact,
    KnownOccurrence,
    SimilarityCandidate,
    SimilarityCorrelation,
)


class RabCorrelationProvider(ABC):
    provider_id: str
    provider_version: str
    production: bool = False

    @abstractmethod
    def correlate(self, artifact: InputArtifact, ssdeep: str | None) -> CorrelationResult:
        """Return read-only preservation intelligence without receiving object bytes."""

    def exact_lookup(self, artifact: InputArtifact) -> CorrelationResult:
        return self.correlate(artifact, None)

    def hash_lookup(self, artifact: InputArtifact) -> CorrelationResult:
        return self.exact_lookup(artifact)

    def similarity_candidates(
        self, artifact: InputArtifact, fingerprint: str
    ) -> list[SimilarityCandidate]:
        return self.correlate(artifact, fingerprint).similarity.candidates

    def relationships(self, artifact: InputArtifact) -> list[KnownOccurrence]:
        return self.exact_lookup(artifact).known_occurrences

    def object_context(self, artifact: InputArtifact) -> list[ExactMatch]:
        return self.exact_lookup(artifact).exact.matches


class UnavailableRabCorrelationProvider(RabCorrelationProvider):
    provider_id = "production-rab"
    provider_version = "1"

    def correlate(self, artifact: InputArtifact, ssdeep: str | None) -> CorrelationResult:
        del artifact, ssdeep
        return CorrelationResult(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            state=CorrelationState.UNAVAILABLE,
            exact=ExactCorrelation(),
            similarity=SimilarityCorrelation(state=CorrelationState.UNAVAILABLE),
            errors=[CorrelationErrorCode.RAB_UNAVAILABLE],
        )


class HTTPRabCorrelationProvider(RabCorrelationProvider):
    """RAB Correlation Protocol v1 client; endpoint is trusted server configuration only."""

    production = True

    def __init__(self, settings: RABCorrelationSettings):
        if not settings.enabled or not settings.endpoint or not settings.credential_file:
            raise ValueError("production RAB correlation is not configured")
        self.settings = settings
        self.endpoint = settings.endpoint
        self.credential_file = settings.credential_file
        self.provider_id = settings.provider_id
        self.provider_version = settings.provider_version

    def _token(self) -> str:
        if self.credential_file.stat().st_mode & 0o077:
            raise OSError("credential permissions are too broad")
        token = self.credential_file.read_text(encoding="utf-8").strip()
        if not token:
            raise OSError("empty credential")
        return token

    def correlate(self, artifact: InputArtifact, ssdeep: str | None) -> CorrelationResult:
        payload: dict[str, object] = {
            "protocol_version": "1",
            "object": {
                "sha256": artifact.hashes.sha256,
                "blake3": artifact.hashes.blake3,
                "sha1": artifact.hashes.sha1,
                "md5": artifact.hashes.md5,
                "size": artifact.byte_size,
            },
        }
        if ssdeep:
            payload["similarity"] = {"algorithm": "ssdeep", "fingerprint": ssdeep}
        try:
            token = self._token()
            timeout = httpx.Timeout(
                self.settings.request_timeout_seconds,
                connect=self.settings.connect_timeout_seconds,
            )
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                with client.stream(
                    "POST",
                    self.endpoint.rstrip("/") + "/v1/correlate",
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                ) as response:
                    if response.status_code in {401, 403}:
                        return self._error(CorrelationErrorCode.RAB_AUTH_FAILED)
                    if response.status_code >= 400:
                        return self._error(CorrelationErrorCode.RAB_PROTOCOL_ERROR)
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > self.settings.maximum_response_bytes:
                            return self._error(CorrelationErrorCode.RAB_RESPONSE_TOO_LARGE)
            document = json.loads(body)
            result = CorrelationResult.model_validate(document)
            return self._validate_and_bound(result, artifact)
        except httpx.TimeoutException:
            return self._error(CorrelationErrorCode.RAB_TIMEOUT)
        except (httpx.HTTPError, OSError):
            return self._error(CorrelationErrorCode.RAB_UNAVAILABLE)
        except (ValueError, TypeError, ValidationError):
            return self._error(CorrelationErrorCode.RAB_PROTOCOL_ERROR)

    def _error(self, code: CorrelationErrorCode) -> CorrelationResult:
        unavailable = code == CorrelationErrorCode.RAB_UNAVAILABLE
        return CorrelationResult(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            state=CorrelationState.UNAVAILABLE if unavailable else CorrelationState.ERROR,
            exact=ExactCorrelation(
                state=ExactLookupState.RAB_UNAVAILABLE if unavailable else ExactLookupState.ERROR,
                completeness=(
                    CorrelationState.UNAVAILABLE if unavailable else CorrelationState.ERROR
                ),
            ),
            similarity=SimilarityCorrelation(
                state=CorrelationState.UNAVAILABLE if unavailable else CorrelationState.ERROR
            ),
            errors=[code],
        )

    def _validate_and_bound(
        self, result: CorrelationResult, artifact: InputArtifact
    ) -> CorrelationResult:
        result.provider_id = self.provider_id
        result.provider_version = self.provider_version
        result.exact.matches = result.exact.matches[: self.settings.max_exact_records]
        result.known_occurrences = result.known_occurrences[: self.settings.max_occurrences]
        result.similarity.candidates = result.similarity.candidates[
            : self.settings.max_similarity_candidates
        ]
        for match in result.exact.matches:
            if match.sha256 != artifact.hashes.sha256 or match.size != artifact.byte_size:
                return self._error(CorrelationErrorCode.RAB_IDENTITY_CONFLICT)
            if match.context:
                match.context.provenance = match.context.provenance[
                    : self.settings.max_provenance_records
                ]
                match.context.known_filenames = [
                    self._clip(value) for value in match.context.known_filenames
                ]
                match.context.source_collections = [
                    self._clip(value) for value in match.context.source_collections
                ]
                match.context.metadata_urls = [
                    self._clip(value) for value in match.context.metadata_urls
                ]
                for record in match.context.provenance:
                    record.source_id = self._clip_optional(record.source_id)
                    record.source_label = self._clip_optional(record.source_label)
                    record.collection = self._clip_optional(record.collection)
                    record.summary = self._clip_optional(record.summary)
        for occurrence in result.known_occurrences:
            occurrence.logical_path = self._clip_optional(occurrence.logical_path)
            occurrence.parent_label = self._clip_optional(occurrence.parent_label)
        for candidate in result.similarity.candidates:
            candidate.query_fingerprint = self._clip(candidate.query_fingerprint)
            candidate.candidate_fingerprint = self._clip(candidate.candidate_fingerprint)
        return result

    def _clip(self, value: str) -> str:
        return value[: self.settings.max_metadata_string_length]

    def _clip_optional(self, value: str | None) -> str | None:
        return self._clip(value) if value is not None else None


class ReferenceRabCorrelationProvider(RabCorrelationProvider):
    """Deterministic qualification provider. It is explicitly not production RAB."""

    provider_id = "avbox-m18-reference-provider"
    provider_version = "1"
    production = False

    def __init__(
        self,
        objects: Mapping[str, ExactMatch],
        occurrences: Mapping[str, list[KnownOccurrence]] | None = None,
        similarities: Mapping[str, list[SimilarityCandidate]] | None = None,
    ):
        self.objects = dict(objects)
        self.occurrences = dict(occurrences or {})
        self.similarities = dict(similarities or {})
        self.requests: list[dict[str, Any]] = []

    def correlate(self, artifact: InputArtifact, ssdeep: str | None) -> CorrelationResult:
        self.requests.append(
            {
                "hashes": artifact.hashes.model_dump(),
                "size": artifact.byte_size,
                "ssdeep": ssdeep,
            }
        )
        match = self.objects.get(artifact.hashes.sha256)
        candidates = list(self.similarities.get(ssdeep or "", []))
        return CorrelationResult(
            provider_id=self.provider_id,
            provider_version=self.provider_version,
            state=CorrelationState.COMPLETE,
            exact=ExactCorrelation(
                state=(ExactLookupState.EXACT_MATCH if match else ExactLookupState.NO_EXACT_MATCH),
                matches=[match] if match else [],
                completeness=CorrelationState.COMPLETE,
            ),
            similarity=SimilarityCorrelation(
                state=CorrelationState.COMPLETE if ssdeep else CorrelationState.NOT_REQUESTED,
                candidates=candidates,
            ),
            known_occurrences=list(self.occurrences.get(artifact.hashes.sha256, [])),
        )
