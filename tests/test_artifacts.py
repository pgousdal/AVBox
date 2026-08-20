import hashlib
from pathlib import Path

from avbox.application import ArtifactService


def test_artifact_hashing(tmp_path: Path) -> None:
    path = tmp_path / "name-is-not-identity.txt"
    path.write_bytes(b"AVBox M0\n")
    artifact = ArtifactService.hash_file(path)
    assert artifact.hashes.sha256 == hashlib.sha256(b"AVBox M0\n").hexdigest()
    assert artifact.identity == artifact.hashes.sha256
    assert len(artifact.hashes.blake3) == 64
