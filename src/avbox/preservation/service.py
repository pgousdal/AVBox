from __future__ import annotations

import json
import os
from pathlib import Path

from avbox.models import InputArtifact, Verdict

from .models import ExternalPreservationManifest


class PreservationService:
    def __init__(self, quarantine: Path):
        self.quarantine = quarantine

    @staticmethod
    def load_external_manifest(path: Path) -> ExternalPreservationManifest:
        return ExternalPreservationManifest.model_validate(
            json.loads(path.read_text(encoding="utf-8"))
        )

    def quarantine_path(self, artifact: InputArtifact) -> Path:
        sha = artifact.hashes.sha256
        return self.quarantine / "sha256" / sha[:2] / sha

    def admit(self, source: Path, artifact: InputArtifact, verdict: Verdict) -> Path:
        if verdict not in {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.PUA}:
            raise ValueError("only malicious, suspicious, or PUA objects may enter quarantine")
        destination = self.quarantine_path(artifact)
        if destination.exists():
            return destination
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = destination.with_suffix(".incoming")
        with source.open("rb") as src, temporary.open("xb") as dst:
            while chunk := src.read(1024 * 1024):
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, destination)
        return destination
