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
from artifact_trust.models import JobRecord, JobRequest, PipelineReport, PolicyInput
from artifact_trust.provenance import (
    envelope_subject_digests,
    load_public_key,
    verify_evidence_directory,
)
from artifact_trust.util import sha256_bytes, write_json


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
        report, _, _ = self._verified_result(job_id)
        return cast(dict[str, object], report.model_dump(mode="json"))

    def html_result(self, job_id: str) -> str:
        _, output, digests = self._verified_result(job_id)
        html_path = output / "report.html"
        try:
            payload = html_path.read_bytes()
        except OSError as exc:
            raise JobError("HTML report is unavailable") from exc
        if sha256_bytes(payload) != digests["report.html"]:
            raise JobError("HTML report digest does not match signed evidence")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JobError("HTML report is not UTF-8") from exc

    def _verified_result(self, job_id: str) -> tuple[PipelineReport, Path, dict[str, str]]:
        record = self.get(job_id)
        if record is None or record.state != "completed" or record.result_path is None:
            raise JobError("job has no completed result")
        try:
            path = (self.settings.work_root / record.result_path).resolve(strict=True)
        except OSError as exc:
            raise JobError("result path is unavailable") from exc
        work_root = self.settings.work_root.resolve()
        if not path.is_relative_to(work_root) or path.name != "report.json":
            raise JobError("invalid result path")
        if self.settings.public_key_path is None or not self.settings.public_key_path.is_file():
            raise JobError("trusted verification key is unavailable")
        output = path.parent
        provenance_path = output / "provenance.dsse.json"
        try:
            envelope_payload = provenance_path.read_text(encoding="utf-8")
            envelope = json.loads(envelope_payload)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JobError("invalid provenance document") from exc
        if not isinstance(envelope, dict):
            raise JobError("invalid provenance document")
        try:
            public_key = load_public_key(self.settings.public_key_path)
        except (OSError, ValueError, TypeError) as exc:
            raise JobError("trusted verification key is invalid") from exc
        verification = verify_evidence_directory(envelope, public_key, output)
        if not (
            verification.signature_valid
            and verification.provenance_valid
            and verification.artifact_digest_valid
            and verification.evidence_digests_valid
        ):
            raise JobError("completed result failed signed evidence verification")
        try:
            digests = envelope_subject_digests(envelope)
            report_bytes = path.read_bytes()
            decision_bytes = (output / "decision.json").read_bytes()
            policy_input_bytes = (output / "policy-input.json").read_bytes()
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise JobError("cannot read signed result evidence") from exc
        if sha256_bytes(report_bytes) != digests["report.json"]:
            raise JobError("report digest does not match signed evidence")
        if sha256_bytes(decision_bytes) != digests["decision.json"]:
            raise JobError("decision digest does not match signed evidence")
        if sha256_bytes(policy_input_bytes) != digests["policy-input.json"]:
            raise JobError("policy input digest does not match signed evidence")
        try:
            report = PipelineReport.model_validate_json(report_bytes)
            decision = json.loads(decision_bytes)
            policy_input = PolicyInput.model_validate_json(policy_input_bytes)
            if not isinstance(decision, dict):
                raise ValueError("decision must be an object")
            if decision.get("report_id") != report.report_id:
                raise ValueError("decision report identifier mismatch")
            if decision.get("policy") != report.policy.model_dump(mode="json"):
                raise ValueError("report and decision policy differ")
            if decision.get("risk") != report.risk.model_dump(mode="json"):
                raise ValueError("report and decision risk differ")
            if decision.get("policy_input") != policy_input.model_dump(mode="json"):
                raise ValueError("decision and policy input differ")
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise JobError("signed result documents are inconsistent") from exc
        return report, output, digests
