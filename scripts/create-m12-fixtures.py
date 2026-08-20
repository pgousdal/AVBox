#!/usr/bin/env python3
"""Create deterministic harmless M1.2 qualification objects; never executable."""

from __future__ import annotations

import argparse
import base64
import shutil
import zipfile
from pathlib import Path

PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    root = args.directory
    root.mkdir(parents=True, exist_ok=True)
    (root / "empty.bin").write_bytes(b"")
    (root / "plain.txt").write_bytes(b"AVBox harmless M1.2 ASCII fixture.\n")
    (root / "binary.bin").write_bytes(bytes(range(256)))
    (root / "pixel.png").write_bytes(PNG_1X1)
    (root / "report.pdf.exe").write_bytes(PNG_1X1)
    (root / "unicode-e\u0301 space.txt").write_bytes(b"harmless unicode filename\n")
    with zipfile.ZipFile(root / "outer.zip", "w", compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo("harmless.txt", date_time=(1980, 1, 1, 0, 0, 0))
        member.external_attr = 0o100644 << 16
        archive.writestr(member, b"not extracted by AVBox M1.2\n")
    shutil.copyfile(root / "outer.zip", root / "archive.zip.exe")


if __name__ == "__main__":
    main()
