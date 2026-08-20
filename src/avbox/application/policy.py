from __future__ import annotations

from avbox.models import ScanPolicy


class PolicyService:
    default_policy = ScanPolicy.READ_ONLY

    @classmethod
    def require_read_only(cls, policy: ScanPolicy) -> None:
        if policy is not ScanPolicy.READ_ONLY:
            raise PermissionError("M0 permits READ_ONLY scans only")
