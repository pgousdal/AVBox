"""Create tiny deterministic, harmless M1.4 qualification fixtures."""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1] / ".state" / "m14-fixtures"
    root.mkdir(parents=True, exist_ok=True)
    (root / "hello.txt").write_bytes(b"hello from avbox m14\n")
    with zipfile.ZipFile(root / "one.zip", "w") as archive:
        archive.writestr("hello.txt", b"hello from avbox m14\n")
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("hello.txt", b"nested hello\n")
    with zipfile.ZipFile(root / "nested.zip", "w") as archive:
        archive.writestr("inner.zip", inner.getvalue())
    with tarfile.open(root / "one.tar", "w") as archive:
        info = tarfile.TarInfo("hello.txt")
        payload = b"tar hello\n"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    payload = b"compressed hello\n"
    (root / "hello.gz").write_bytes(gzip.compress(payload))
    (root / "hello.bz2").write_bytes(bz2.compress(payload))
    (root / "hello.xz").write_bytes(lzma.compress(payload))
    with zipfile.ZipFile(root / "duplicates.zip", "w") as archive:
        archive.writestr("same.txt", b"a")
        archive.writestr("same.txt", b"b")
        archive.writestr("copy.txt", b"b")
    with zipfile.ZipFile(root / "unsafe.zip", "w") as archive:
        archive.writestr("../../escape.txt", b"no")
        archive.writestr("/absolute.txt", b"no")
    raw = (root / "one.zip").read_bytes()
    (root / "corrupt.zip").write_bytes(raw[: max(1, len(raw) // 3)])


if __name__ == "__main__":
    main()
