from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from avbox.models import JobStatus, ScanJob, ScannerRuntimeStatus


class JobService:
    """Mutable operational state only; registry/catalog truth remains YAML."""

    def __init__(self, database: Path):
        database.parent.mkdir(parents=True, exist_ok=True)
        self.database = database
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS jobs "
                "(job_id TEXT PRIMARY KEY, status TEXT NOT NULL, document TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS scanner_runtime "
                "(scanner_id TEXT PRIMARY KEY, document TEXT NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database)

    def save(self, job: ScanJob) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO jobs VALUES (?, ?, ?)",
                (str(job.job_id), job.status, job.model_dump_json()),
            )

    def list(self) -> list[ScanJob]:
        with self._connect() as connection:
            rows = connection.execute("SELECT document FROM jobs ORDER BY rowid DESC").fetchall()
        return [ScanJob.model_validate(json.loads(row[0])) for row in rows]

    def get(self, job_id: str) -> ScanJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT document FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return ScanJob.model_validate(json.loads(row[0])) if row else None

    def transition(self, job: ScanJob, target: JobStatus) -> ScanJob:
        job.transition(target)
        self.save(job)
        return job

    def save_scanner_status(self, status: ScannerRuntimeStatus) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO scanner_runtime VALUES (?, ?)",
                (status.scanner_id, status.model_dump_json()),
            )

    def scanner_statuses(self) -> dict[str, ScannerRuntimeStatus]:
        with self._connect() as connection:
            rows = connection.execute("SELECT scanner_id, document FROM scanner_runtime").fetchall()
        return {row[0]: ScannerRuntimeStatus.model_validate(json.loads(row[1])) for row in rows}
