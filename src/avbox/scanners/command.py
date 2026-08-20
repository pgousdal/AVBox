from __future__ import annotations

import hashlib
import os
import resource
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    isolated: bool = False


class IsolatedCommandRunner:
    """Bounded scanner execution with a read-only host view and no network when bwrap works."""

    def __init__(self, *, timeout: int, memory_mib: int = 1024, use_bwrap: bool = True):
        self.timeout = timeout
        self.memory_mib = memory_mib
        self.use_bwrap = use_bwrap

    def run(
        self, argv: list[str], *, cwd: Path, read_only_input: Path | None = None
    ) -> CommandResult:
        if not argv or any(
            arg in {"--remove", "--move", "--copy", "--delete", "--clean"} for arg in argv
        ):
            raise ValueError("remediation options are forbidden by READ_ONLY policy")
        command = argv
        isolated = False
        if self.use_bwrap and shutil.which("bwrap"):
            command = [
                "bwrap",
                "--die-with-parent",
                "--new-session",
                "--unshare-net",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                "--chdir",
                str(cwd),
                "--",
            ] + argv
            isolated = True
        started = time.monotonic()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
        }

        def limits() -> None:
            maximum = self.memory_mib * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (maximum, maximum))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                check=False,
                preexec_fn=limits,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (
                exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
            )
            stderr = (
                exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
            )
            return CommandResult(
                tuple(argv),
                124,
                stdout or "",
                stderr or "",
                time.monotonic() - started,
                timed_out=True,
                isolated=isolated,
            )
        return CommandResult(
            tuple(argv),
            completed.returncode,
            completed.stdout,
            completed.stderr,
            time.monotonic() - started,
            isolated=isolated,
        )


def store_raw_output(root: Path, job_id: str, scanner_id: str, result: CommandResult) -> str:
    directory = root / job_id
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (result.stdout + ("\n[stderr]\n" + result.stderr if result.stderr else "")).encode()
    digest = hashlib.sha256(payload).hexdigest()
    path = directory / f"{scanner_id}-{digest[:16]}.log"
    if not path.exists():
        path.write_bytes(payload)
        path.chmod(0o400)
    return f"raw-output/{job_id}/{path.name}"
