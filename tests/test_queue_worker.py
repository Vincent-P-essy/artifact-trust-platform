from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from artifact_trust.config import Settings
from artifact_trust.errors import JobError
from artifact_trust.models import JobRequest, SourceSpec
from artifact_trust.queue import FileQueue
from artifact_trust.worker import _limit_child, process_next_job, run_worker


def _request() -> JobRequest:
    return JobRequest(
        source=SourceSpec(kind="fixture", location="safe-app"), policy_engine="fallback"
    )


def test_queue_lifecycle_failure_and_invalid_lookup(settings: Settings) -> None:
    queue = FileQueue(settings)
    first = queue.enqueue(_request())
    second = queue.enqueue(_request())
    assert queue.get("../escape") is None
    assert {item.id for item in queue.list()} == {first.id, second.id}
    claimed = queue.claim()
    assert claimed is not None and claimed.state == "running"
    failed = queue.fail(claimed, "scan_error", "  controlled\x00  failure  ")
    assert failed.state == "failed"
    assert failed.error_message == "controlled failure"
    with pytest.raises(JobError, match="no completed result"):
        queue.result(failed.id)


def test_queue_skips_corrupt_record(settings: Settings) -> None:
    queue = FileQueue(settings)
    (settings.work_root / "pending" / "broken.json").write_text("not-json", encoding="utf-8")
    assert queue.list() == []
    assert queue.claim() is None
    assert (settings.work_root / "failed" / "broken.invalid").is_file()


def test_worker_handles_child_failure(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    queue = FileQueue(settings)
    record = queue.enqueue(_request())
    monkeypatch.setattr(
        "artifact_trust.worker.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=7, stderr="controlled child error\n"),
    )
    assert process_next_job(settings) is True
    failed = queue.get(record.id)
    assert failed is not None and failed.state == "failed"
    assert failed.error_code == "worker_failed"


def test_worker_handles_timeout(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    queue = FileQueue(settings)
    record = queue.enqueue(_request())

    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(["python"], 1)

    monkeypatch.setattr("artifact_trust.worker.subprocess.run", timeout)
    assert process_next_job(settings) is True
    failed = queue.get(record.id)
    assert failed is not None and failed.error_code == "worker_timeout"


def test_worker_handles_missing_result(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    queue = FileQueue(settings)
    record = queue.enqueue(_request())
    monkeypatch.setattr(
        "artifact_trust.worker.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stderr=""),
    )
    assert process_next_job(settings) is True
    failed = queue.get(record.id)
    assert failed is not None and failed.error_code == "missing_result"


def test_worker_once_returns_when_queue_empty(settings: Settings) -> None:
    assert process_next_job(settings) is False
    run_worker(settings, once=True)


def test_resource_limit_function_sets_all_limits(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[int, tuple[int, int]]] = []
    monkeypatch.setattr("artifact_trust.worker.os.umask", lambda _: 0)
    monkeypatch.setattr(
        "artifact_trust.worker.resource.setrlimit", lambda key, value: calls.append((key, value))
    )
    _limit_child(settings)
    assert len(calls) >= 4
