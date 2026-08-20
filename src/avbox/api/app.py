from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from avbox.runtime import Context, build_context


def create_app(context: Context | None = None) -> FastAPI:
    ctx = context or build_context()
    app = FastAPI(title="AVBox", version="0.1.0", docs_url="/api/docs", redoc_url=None)
    app.state.context = ctx

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "milestone": "M0", "scanner_runtime": "not-installed"}

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
        return f"""<!doctype html><html><head><meta charset=utf-8><title>AVBox M0</title></head>
<body><h1>AVBox status</h1><dl><dt>Milestone</dt><dd>M0 Foundation</dd>
<dt>Status</dt><dd>ready; no scanner engines installed</dd>
<dt>Configured platforms</dt><dd>{platforms_count}</dd>
<dt>Configured scanners</dt><dd>{scanners_count}</dd><dt>Job count</dt><dd>{jobs_count}</dd>
<dt>Quarantine count</dt><dd>{quarantine_count}</dd></dl></body></html>"""

    return app


app = create_app()
