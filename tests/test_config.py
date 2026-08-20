from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from avbox.config import AppSettings


def test_configuration_loads() -> None:
    settings = AppSettings.from_yaml(Path("config/avbox.yaml"))
    assert settings.api.host == "127.0.0.1"


def test_lan_binding_requires_explicit_opt_in(tmp_path: Path) -> None:
    data = yaml.safe_load(Path("config/avbox.yaml").read_text())
    data["api"]["host"] = "0.0.0.0"
    path = tmp_path / "unsafe.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ValidationError, match="explicit_lan_exposure"):
        AppSettings.from_yaml(path)


def test_missing_required_paths_fails() -> None:
    with pytest.raises(ValidationError):
        AppSettings.model_validate({})
