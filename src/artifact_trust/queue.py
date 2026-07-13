"""Atomic filesystem queue shared by API and isolated worker services."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from artifact_trust.config import Settings
from artifact_trust.errors import JobError
from artifact_trust.models import JobRecord, JobRequest
from artifact_trust.util import write_json


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class FileQueue:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        settings.ensure_directories()

    def _path(self, state: str, job_id: str) -> Path:
        return self.settings.work_root / state / f"{job_id}.json"

    @staticmethod
    def _write_record(destination: Path, record: JobRecord) -> None:
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        write_json(temporary, record.model_dump(mode="json"))
        os.replace(temporary, destination)

    def enqueue(self, request: JobRequest) -> JobRecord:
        now = _now()
        record = JobRecord(
            id=uuid.uuid4().hex,
            state="pending",
            request=request,
            created_at=now,
            updated_at=now,
        )
        destination = self._path("pending", record.id)
        self._write_record(destination, record)
        return record

    def get(self, job_id: str) -> JobRecord | None:
        if not job_id.isalnum() or len(job_id) > 64:
            return None
        for state in ("pending", "running", "completed", "failed"):
            path = self._path(state, job_id)
            if path.exists():
                return JobRecord.model_validate_json(path.read_text(encoding="utf-8"))
        return None

    def list(self, limit: int = 50) -> list[JobRecord]:
        records: list[JobRecord] = []
        for state in ("pending", "running", "completed", "failed"):
            for path in (self.settings.work_root / state).glob("*.json"):
                try:
                    records.append(JobRecord.model_validate_json(path.read_text(encoding="utf-8")))
                except (ValueError, OSError):
                    continue
        return sorted(records, key=lambda item: (item.created_at, item.id), reverse=True)[:limit]

    def claim(self) -> JobRecord | None:
        for pending in sorted((self.settings.work_root / "pending").glob("*.json")):
            running = self._path("running", pending.stem)
            try:
                os.replace(pending, running)
            except FileNotFoundError:
                continue
            try:
                record = JobRecord.model_validate_json(running.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                os.replace(running, self.settings.work_root / "failed" / f"{pending.stem}.invalid")
                continue
            claimed = record.model_copy(update={"state": "running", "updated_at": _now()})
            self._write_record(running, claimed)
            return claimed
        return None

    def complete(self, record: JobRecord, result_path: Path) -> JobRecord:
        completed = record.model_copy(
            update={
                "state": "completed",
                "updated_at": _now(),
                "result_path": str(result_path.relative_to(self.settings.work_root)),
            }
        )
        source = self._path("running", record.id)
        destination = self._path("completed", record.id)
        self._write_record(destination, completed)
        source.unlink(missing_ok=True)
        return completed

    def fail(self, record: JobRecord, code: str, message: str) -> JobRecord:
        safe_message = " ".join(message.replace("\x00", "").split())[:300]
        failed = record.model_copy(
            update={
                "state": "failed",
                "updated_at": _now(),
                "error_code": code[:80],
                "error_message": safe_message or "worker failed",
            }
        )
        source = self._path("running", record.id)
        destination = self._path("failed", record.id)
        self._write_record(destination, failed)
        source.unlink(missing_ok=True)
        return failed

    def result(self, job_id: str) -> dict[str, object]:
        record = self.get(job_id)
        if record is None or record.state != "completed" or record.result_path is None:
            raise JobError("job has no completed result")
        path = (self.settings.work_root / record.result_path).resolve()
        if not path.is_relative_to(self.settings.work_root) or path.name != "report.json":
            raise JobError("invalid result path")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise JobError("invalid result document")
        return cast(dict[str, object], payload)
