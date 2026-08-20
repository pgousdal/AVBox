from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .common import QualificationState


class ScannerRuntimeStatus(BaseModel):
    scanner_id: str
    qualification_state: QualificationState
    installed_version: str | None = None
    definition_state: dict[str, str | int | None] = Field(default_factory=dict)
    last_probe: datetime | None = None
    last_update: datetime | None = None
    detail: str | None = None
