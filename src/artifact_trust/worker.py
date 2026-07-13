"""Worker process boundary and resource limits."""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import time

from artifact_trust.config import Settings
from artifact_trust.queue import FileQueue


def _child_environment(settings: Settings) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": str(settings.source_date_epoch),
        "ATP_WORK_ROOT": str(settings.work_root),
        "ATP_FIXTURES_ROOT": str(settings.fixtures_root),
        "ATP_ALLOWED_LOCAL_ROOTS": os.pathsep.join(
            str(item) for item in settings.allowed_local_roots
        ),
        "ATP_ALLOWED_GIT_HOSTS": ",".join(settings.allowed_git_hosts),
        "ATP_ALLOW_NETWORK": "1" if settings.network_enabled else "0",
        "ATP_CPU_SECONDS": str(settings.sandbox.cpu_seconds),
        "ATP_MEMORY_MB": str(settings.sandbox.memory_mb),
        "ATP_MAX_FILES": str(settings.sandbox.max_files),
        "ATP_MAX_FILE_SIZE": str(settings.sandbox.max_file_size_bytes),
        "ATP_MAX_TOTAL_SIZE": str(settings.sandbox.max_total_size_bytes),
        "ATP_MAX_PIDS": str(settings.sandbox.pids),
    }
    if settings.private_key_path:
        environment["ATP_PRIVATE_KEY"] = str(settings.private_key_path)
    if settings.public_key_path:
        environment["ATP_PUBLIC_KEY"] = str(settings.public_key_path)
    python_path = os.environ.get("PYTHONPATH")
    if python_path:
        environment["PYTHONPATH"] = python_path
    return environment


def _limit_child(settings: Settings) -> None:
    os.umask(0o027)
    memory = settings.sandbox.memory_mb * 1024 * 1024
    resource.setrlimit(
        resource.RLIMIT_CPU, (settings.sandbox.cpu_seconds, settings.sandbox.cpu_seconds)
    )
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (settings.sandbox.max_total_size_bytes, settings.sandbox.max_total_size_bytes),
    )
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (settings.sandbox.pids, settings.sandbox.pids))


def process_next_job(settings: Settings) -> bool:
    queue = FileQueue(settings)
    record = queue.claim()
    if record is None:
        return False
    output = settings.work_root / "results" / record.id
    command = [sys.executable, "-m", "artifact_trust.worker_child", "--job-id", record.id]
    try:
        result = subprocess.run(
            command,
            env=_child_environment(settings),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=settings.sandbox.cpu_seconds * 3,
            check=False,
            preexec_fn=lambda: _limit_child(settings),
        )
    except subprocess.TimeoutExpired:
        queue.fail(record, "worker_timeout", "worker exceeded its wall-clock limit")
        return True
    if result.returncode != 0:
        detail = (
            result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "worker exited"
        )
        queue.fail(record, "worker_failed", detail)
        return True
    report_path = output / "report.json"
    if not report_path.is_file():
        queue.fail(record, "missing_result", "worker produced no report")
        return True
    queue.complete(record, report_path)
    return True


def run_worker(settings: Settings, once: bool = False, poll_seconds: float = 1.0) -> None:
    while True:
        processed = process_next_job(settings)
        if once:
            return
        if not processed:
            time.sleep(max(0.1, min(poll_seconds, 30.0)))
