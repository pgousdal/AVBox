from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from pydantic import ValidationError

from avbox.application import ArtifactService
from avbox.runtime import build_context


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="avbox")
    root.add_argument("--config", type=Path)
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    registry = sub.add_parser("registry").add_subparsers(dest="registry_command", required=True)
    registry.add_parser("validate")
    registry.add_parser("platforms")
    registry.add_parser("scanners")
    job = sub.add_parser("job").add_subparsers(dest="job_command", required=True)
    job.add_parser("list")
    artifact = sub.add_parser("artifact").add_subparsers(dest="artifact_command", required=True)
    hashing = artifact.add_parser("hash")
    hashing.add_argument("file", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        context = build_context(args.config)
    except (OSError, ValueError, ValidationError) as exc:
        print(f"configuration/registry error: {exc}", file=sys.stderr)
        return 2
    if args.command == "doctor":
        checks = {
            "configuration": "ok",
            "registry": "ok",
            "sqlite_parent": str(context.settings.storage.sqlite_path.parent),
            "blake3": "ok" if shutil.which("b3sum") or _has_blake3() else "missing",
            "api_binding": f"{context.settings.api.host}:{context.settings.api.port}",
            "scanner_engines_required": False,
        }
        print(json.dumps(checks, indent=2))
        return 0 if checks["blake3"] == "ok" else 1
    if args.command == "registry":
        if args.registry_command == "validate":
            print("registry valid")
            return 0
        values = (
            context.registry.registry.platforms
            if args.registry_command == "platforms"
            else context.registry.registry.products
        )
        for item in values:
            label = item.label if hasattr(item, "label") else item.vendor + " " + item.product
            print(f"{item.id}\t{label}")
        return 0
    if args.command == "job":
        print(json.dumps([job.model_dump(mode="json") for job in context.jobs.list()], indent=2))
        return 0
    if args.command == "artifact":
        artifact = ArtifactService.hash_file(args.file)
        print(artifact.model_dump_json(indent=2))
        return 0
    return 2


def _has_blake3() -> bool:
    try:
        import blake3  # noqa: F401
    except ImportError:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
