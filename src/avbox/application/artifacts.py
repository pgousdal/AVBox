from __future__ import annotations

import hashlib
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from avbox.models import Hashes, InputArtifact, Rights


class ArtifactService:
    @staticmethod
    def hash_file(
        path: Path, *, source: str = "local-cli", media_type: str = "application/octet-stream"
    ) -> InputArtifact:
        if not path.is_file():
            raise ValueError(f"not a regular file: {path}")
        digests = {name: hashlib.new(name) for name in ("sha256", "sha1", "md5")}
        try:
            import blake3
        except ImportError as exc:
            if not shutil.which("b3sum"):
                raise RuntimeError("BLAKE3 support requires Python blake3 or b3sum") from exc
            b3 = None
        else:
            b3 = blake3.blake3()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                for digest in digests.values():
                    digest.update(chunk)
                if b3 is not None:
                    b3.update(chunk)
        blake3_value = (
            b3.hexdigest()
            if b3 is not None
            else subprocess.run(
                ["b3sum", "--no-names", str(path)], check=True, capture_output=True, text=True
            ).stdout.split()[0]
        )
        hashes = Hashes(
            **{name: digest.hexdigest() for name, digest in digests.items()}, blake3=blake3_value
        )
        return InputArtifact(
            hashes=hashes,
            byte_size=path.stat().st_size,
            filename=path.name,
            media_type=media_type,
            source=source,
            submitted_at=datetime.now(UTC),
            rights=Rights(),
        )
