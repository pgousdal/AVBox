"""Job facade shared by future CLI, API, and worker entry points."""

from avbox.application import JobService
from avbox.models import JobStatus, ScanJob, ScannerResult

__all__ = ["JobService", "JobStatus", "ScanJob", "ScannerResult"]
