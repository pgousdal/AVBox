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
            connection.execute(
                "CREATE TABLE IF NOT EXISTS rab_jobs "
                "(job_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, "
                "client_request_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, "
                "fingerprint TEXT NOT NULL, profile TEXT NOT NULL, upload_path TEXT, "
                "document TEXT NOT NULL, UNIQUE(client_id, idempotency_key))"
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

    def save_rab_job(
        self,
        *,
        job_id: str,
        client_id: str,
        client_request_id: str,
        idempotency_key: str,
        fingerprint: str,
        profile: str,
        upload_path: str | None,
        document: dict[str, object],
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO rab_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    job_id,
                    client_id,
                    client_request_id,
                    idempotency_key,
                    fingerprint,
                    profile,
                    upload_path,
                    json.dumps(document, sort_keys=True),
                ),
            )

    def rab_by_idempotency(self, client_id: str, key: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT job_id, fingerprint, profile, document FROM rab_jobs "
                "WHERE client_id = ? AND idempotency_key = ?",
                (client_id, key),
            ).fetchone()
        if not row:
            return None
        return {
            "job_id": row[0],
            "fingerprint": row[1],
            "profile": row[2],
            "document": json.loads(row[3]),
        }

    def rab_job(self, job_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT client_id, client_request_id, profile, upload_path, document "
                "FROM rab_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if not row:
            return None
        return {
            "client_id": row[0],
            "client_request_id": row[1],
            "profile": row[2],
            "upload_path": row[3],
            "document": json.loads(row[4]),
        }

    def reconcile_interrupted(self) -> int:
        count = 0
        for job in self.list():
            if job.source.startswith("rab:") and job.status in {
                JobStatus.STAGED,
                JobStatus.QUEUED,
                JobStatus.RUNNING,
            }:
                job.errors.append("ANALYSIS_FAILED: interrupted by service restart")
                job.transition(JobStatus.FAILED)
                self.save(job)
                count += 1
        return count
