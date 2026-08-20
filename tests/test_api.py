import asyncio
from pathlib import Path

from avbox.api import create_app
from avbox.application import JobService
from avbox.config import AppSettings
from avbox.registry import RegistryService
from avbox.runtime import Context


def test_api_and_status_page(tmp_path: Path) -> None:
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    context = Context(
        settings,
        RegistryService(Path("config/registry/registry.yaml")),
        JobService(tmp_path / "jobs.db"),
    )
    app = create_app(context)
    routes = {route.path: route for route in app.routes if hasattr(route, "path")}
    assert asyncio.run(routes["/health"].endpoint())["status"] == "ok"
    assert asyncio.run(routes["/api/v1/platforms"].endpoint())
    assert asyncio.run(routes["/api/v1/scanners"].endpoint())
    assert asyncio.run(routes["/api/v1/jobs"].endpoint()) == []
    expected = {"/health", "/api/v1/platforms", "/api/v1/scanners", "/api/v1/jobs", "/"}
    assert expected <= routes.keys()
