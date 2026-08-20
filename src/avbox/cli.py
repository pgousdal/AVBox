from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
from pydantic import ValidationError

from avbox.application import ArtifactService
from avbox.models import QualificationState, ScannerRuntimeStatus
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
    show = job.add_parser("show")
    show.add_argument("job_id")
    artifact = sub.add_parser("artifact").add_subparsers(dest="artifact_command", required=True)
    hashing = artifact.add_parser("hash")
    hashing.add_argument("file", type=Path)
    scanner = sub.add_parser("scanner").add_subparsers(dest="scanner_command", required=True)
    scanner.add_parser("status")
    probe = scanner.add_parser("probe")
    probe.add_argument("scanner", nargs="?")
    update = scanner.add_parser("update")
    update.add_argument("scanner")
    scan = sub.add_parser("scan")
    scan.add_argument("file", type=Path)
    scan.add_argument("--scanner", action="append", dest="scanners")
    analyze = sub.add_parser("analyze")
    analyze.add_argument("file", type=Path)
    analyze.add_argument("--profile", default="identification-default@1")
    system_scan = sub.add_parser("system-scan")
    system_scan.add_argument("--scanner", action="append", dest="scanners")
    rab = sub.add_parser("rab")
    rab.add_argument("--url", default=os.environ.get("AVBOX_RAB_URL", "http://127.0.0.1:8080"))
    rab_sub = rab.add_subparsers(dest="rab_command", required=True)
    rab_sub.add_parser("capabilities")
    rab_job = rab_sub.add_parser("job")
    rab_job.add_argument("job_id")
    rab_results = rab_sub.add_parser("results")
    rab_results.add_argument("job_id")
    rab_submit = rab_sub.add_parser("submit")
    rab_submit.add_argument("file", type=Path)
    rab_submit.add_argument("--profile", default="security-default@1")
    rab_submit.add_argument("--client-request-id", default=None)
    rab_submit.add_argument("--idempotency-key", default=None)
    rab_submit.add_argument("--media-type", default="application/octet-stream")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    # The HTTP client must not build a local RABService: doing so would run
    # restart reconciliation against the server's SQLite database.
    if args.command == "rab":
        return _rab_client(args)
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
            "scanner_runtime_optional_for_control_plane": True,
        }
        print(json.dumps(checks, indent=2))
        return 0 if checks["blake3"] == "ok" else 1
    if args.command == "registry":
        if args.registry_command == "validate":
            print("registry valid")
            return 0
        registry_values = (
            context.registry.registry.platforms
            if args.registry_command == "platforms"
            else context.registry.registry.products
        )
        for item in registry_values:
            label = item.label if hasattr(item, "label") else item.vendor + " " + item.product
            print(f"{item.id}\t{label}")
        return 0
    if args.command == "job":
        if args.job_command == "list":
            documents = [job.model_dump(mode="json") for job in context.jobs.list()]
            print(json.dumps(documents, indent=2))
            return 0
        found = context.jobs.get(args.job_id)
        if found is None:
            print("job not found", file=sys.stderr)
            return 1
        print(found.model_dump_json(indent=2))
        return 0
    if args.command == "artifact":
        artifact = ArtifactService.hash_file(args.file)
        print(artifact.model_dump_json(indent=2))
        return 0
    if args.command == "scanner":
        all_adapters = list(context.adapters.items()) + list(context.system_adapters.items())
        if args.scanner_command == "status":
            persisted = context.jobs.scanner_statuses()
            statuses = {
                name: {
                    "observed": vars(adapter.probe()),
                    "qualification": (
                        persisted[name].model_dump(mode="json") if name in persisted else None
                    ),
                }
                for name, adapter in all_adapters
            }
            print(json.dumps(statuses, indent=2, default=str))
            return 0
        selected = [args.scanner] if args.scanner else [name for name, _ in all_adapters]
        if args.scanner_command == "probe":
            statuses = {
                name: vars(adapter.probe()) for name, adapter in all_adapters if name in selected
            }
            print(json.dumps(statuses, indent=2, default=str))
            return 0
        adapter = dict(all_adapters).get(args.scanner)
        if adapter is None:
            print("unknown scanner", file=sys.stderr)
            return 2
        try:
            result = cast(Any, adapter).update()
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        observed = cast(Any, adapter).probe()
        previous = context.jobs.scanner_statuses().get(args.scanner)
        successful_state = (
            previous.qualification_state
            if previous and previous.qualification_state == QualificationState.QUALIFIED
            else QualificationState.PROBED
        )
        context.jobs.save_scanner_status(
            ScannerRuntimeStatus(
                scanner_id=args.scanner,
                qualification_state=(
                    successful_state if result.exit_code == 0 else QualificationState.DEGRADED
                ),
                installed_version=observed.version,
                definition_state=observed.definition_state or {},
                last_probe=datetime.now(UTC),
                last_update=datetime.now(UTC),
                detail="explicit update completed"
                if result.exit_code == 0
                else "explicit update failed",
            )
        )
        print(json.dumps(result.__dict__, indent=2, default=str))
        return 0 if result.exit_code == 0 else 1
    if args.command in {"scan", "analyze"}:
        if args.command == "analyze":
            if context.rab_protocol is None:
                raise RuntimeError("analysis profile service is unavailable")
            profile = context.rab_protocol.profile_map.get(args.profile)
            if profile is None:
                print("unknown analysis profile", file=sys.stderr)
                return 2
            selected = profile.analyzers
        else:
            selected = args.scanners or context.settings.runtime.default_file_detectors
        if context.scans is None:
            raise RuntimeError("scan service is unavailable")
        result = context.scans.scan_file(args.file, selected)
        print(result.model_dump_json(indent=2))
        return 0 if result.status.value in {"COMPLETE", "QUARANTINED"} else 1
    if args.command == "system-scan":
        selected = args.scanners or list(context.system_adapters)
        if context.scans is None:
            raise RuntimeError("scan service is unavailable")
        results = context.scans.system_scan(selected)
        print(json.dumps([item.model_dump(mode="json") for item in results], indent=2))
        return 0
    return 2


def _rab_client(args: Any) -> int:
    token = os.environ.get("AVBOX_RAB_TOKEN")
    if not token:
        print("AVBOX_RAB_TOKEN is required", file=sys.stderr)
        return 2
    headers = {"Authorization": f"Bearer {token}"}
    base = args.url.rstrip("/") + "/api/v1/rab"
    with httpx.Client(timeout=30) as http:
        if args.rab_command == "capabilities":
            response = http.get(base + "/capabilities", headers=headers)
        elif args.rab_command == "job":
            response = http.get(base + f"/analysis-jobs/{args.job_id}", headers=headers)
        elif args.rab_command == "results":
            response = http.get(
                base + f"/analysis-jobs/{args.job_id}/results", headers=headers
            )
        else:
            request_id = args.client_request_id or str(uuid.uuid4())
            idempotency = args.idempotency_key or request_id
            headers["Idempotency-Key"] = idempotency
            with args.file.open("rb") as stream:
                expected = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    expected.update(chunk)
                stream.seek(0)
                response = http.post(
                    base + "/analysis-jobs",
                    headers=headers,
                    data={
                        "client_request_id": request_id,
                        "expected_sha256": expected.hexdigest(),
                        "profile": args.profile,
                        "protocol_version": "1",
                        "filename": args.file.name,
                        "media_type": args.media_type,
                    },
                    files={"object_bytes": (args.file.name, stream, args.media_type)},
                )
    print(json.dumps(response.json(), indent=2))
    return 0 if response.status_code < 400 else 1


def _has_blake3() -> bool:
    try:
        import blake3  # noqa: F401
    except ImportError:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
