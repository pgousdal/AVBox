from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from avbox.protocol import RABProtocolError
from avbox.runtime import Context, build_context

from .rab import protocol_error_handler
from .rab import router as rab_router


def create_app(context: Context | None = None) -> FastAPI:
    ctx = context or build_context()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        if ctx.rab_protocol is not None:
            ctx.rab_protocol.shutdown()

    app = FastAPI(
        title="AVBox",
        version="0.4.0",
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.context = ctx
    app.add_exception_handler(RABProtocolError, cast(Any, protocol_error_handler))
    app.include_router(rab_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "milestone": "M1.8", "scanner_runtime": "enabled"}

    @app.get("/api/v1/platforms")
    async def platforms() -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in ctx.registry.registry.platforms]

    @app.get("/api/v1/scanners")
    async def scanners() -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in ctx.registry.registry.products]

    @app.get("/api/v1/jobs")
    async def jobs() -> list[dict[str, object]]:
        return [
            job.model_dump(mode="json", exclude={"input_artifact": {"filename", "source"}})
            for job in ctx.jobs.list()
        ]

    @app.get("/api/v1/jobs/{job_id}")
    async def job(job_id: str) -> dict[str, object]:
        found = ctx.jobs.get(job_id)
        return (
            {"status": "not-found"}
            if found is None
            else found.model_dump(mode="json", exclude={"input_artifact": {"filename", "source"}})
        )

    @app.get("/api/v1/jobs/{job_id}/results")
    async def job_results(job_id: str) -> list[dict[str, object]]:
        found = ctx.jobs.get(job_id)
        if found is None:
            return []
        return [item.model_dump(mode="json") for item in found.scanner_results]

    @app.get("/api/v1/scanners/status")
    async def scanner_status() -> list[dict[str, object]]:
        values: list[dict[str, object]] = []
        persisted = ctx.jobs.scanner_statuses()
        adapters = list(ctx.adapters.items()) + list(ctx.system_adapters.items())
        for name, adapter in adapters:
            probe = adapter.probe()
            values.append(
                {
                    "id": name,
                    "observed": vars(probe),
                    "qualification": (
                        persisted[name].model_dump(mode="json") if name in persisted else None
                    ),
                }
            )
        return values

    @app.get("/", response_class=HTMLResponse)
    async def status_page(request: Request) -> str:
        del request
        platforms_count = len(ctx.registry.registry.platforms)
        scanners_count = len(ctx.registry.registry.products)
        jobs_count = len(ctx.jobs.list())
        quarantine_root = ctx.settings.paths.quarantine / "sha256"
        quarantine_count = (
            sum(1 for item in quarantine_root.glob("*/*") if item.is_file())
            if quarantine_root.exists()
            else 0
        )
        rab_enabled = bool(ctx.rab_protocol and ctx.rab_protocol.settings.enabled)
        rab_queued = ctx.rab_protocol.queue.qsize() if ctx.rab_protocol else 0
        correlation_service = ctx.scans.correlation_service if ctx.scans else None
        correlation_provider = correlation_service.provider if correlation_service else None
        adapters = list(ctx.adapters.items()) + list(ctx.system_adapters.items())
        persisted = ctx.jobs.scanner_statuses()
        scanner_rows = "".join(
            f"<tr><td>{name}</td><td>{adapter.scanner_class}</td><td>"
            f"{persisted[name].qualification_state if name in persisted else adapter.probe().state}"
            "</td>"
            f"<td>{adapter.probe().version or 'unknown'}</td></tr>"
            for name, adapter in adapters
        )
        generic_rows = "".join(
            f"<tr><td>{name}</td><td>{adapter.analyzer_class}</td><td>"
            f"{persisted[name].qualification_state if name in persisted else adapter.probe().state}"
            f"</td><td>{adapter.probe().version or 'unknown'}</td></tr>"
            for name, adapter in ctx.generic_analyzers.items()
        )
        recursive = getattr(ctx.scans, "recursive_analyzer", None)
        container_summary = (
            "qualified: ZIP, tar, gzip, bzip2, xz, LHA, ISO9660, 7z, "
            "FAT12/16/32, ADF OFS/FFS, MBR primary, RDB/HDF; "
            "deferred: EBR, GPT, flat HDF, CAB, ARJ, LZX, RAR, Atari, Apple II, HFS; "
            f"max depth {recursive.budget.max_recursion_depth}; "
            f"max children {recursive.budget.max_total_children}"
            if recursive is not None
            else "not available"
        )
        return f"""<!doctype html><html><head><meta charset=utf-8><title>AVBox M1.8</title></head>
<body><h1>AVBox status</h1><dl><dt>Milestone</dt><dd>M1.8 RAB Correlation Intelligence</dd>
<dt>Status</dt><dd>current Linux detector runtime</dd>
<dt>Configured platforms</dt><dd>{platforms_count}</dd>
<dt>Configured scanners</dt><dd>{scanners_count}</dd><dt>Job count</dt><dd>{jobs_count}</dd>
<dt>Quarantine count</dt><dd>{quarantine_count}</dd></dl>
<dl><dt>RAB Protocol v1 enabled</dt><dd>{rab_enabled}</dd>
<dt>RAB queued jobs</dt><dd>{rab_queued}</dd></dl>
<dl><dt>Production RAB correlation</dt>
<dd>{
            "configured"
            if correlation_provider and correlation_provider.production
            else "not available"
        }</dd>
<dt>Correlation provider</dt>
<dd>{correlation_provider.provider_id if correlation_provider else "none"}</dd>
<dt>Exact/occurrence/ssdeep</dt><dd>qualified</dd><dt>TLSH</dt><dd>deferred</dd></dl>
<table><thead><tr><th>Detector</th><th>Class</th><th>Runtime state</th><th>Version</th></tr></thead>
<tbody>{scanner_rows}</tbody></table>
<h2>Generic analyzers</h2><table><thead><tr><th>Analyzer</th><th>Class</th>
<th>Runtime state</th><th>Version</th></tr></thead><tbody>{generic_rows}</tbody></table>
<h2>Recursive object analysis</h2><p>{container_summary}</p>
</body></html>"""

    return app


app = create_app()
