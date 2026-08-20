from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from avbox.models import JobStatus, ScanJob


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

    def transition(self, job: ScanJob, target: JobStatus) -> ScanJob:
        job.transition(target)
        self.save(job)
        return job
