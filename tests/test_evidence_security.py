from __future__ import annotations

import base64
import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from artifact_trust.config import Settings
from artifact_trust.errors import JobError
from artifact_trust.models import (
    JobRequest,
    ManifestAnalysis,
    MaterializedSource,
    SourceSpec,
)
from artifact_trust.pipeline import run_pipeline
from artifact_trust.provenance import (
    EVIDENCE_SUBJECTS,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    build_statement,
    envelope_subject_digests,
    load_private_key,
    load_public_key,
    sign_statement,
    subject_digests,
    verify_evidence_directory,
)
from artifact_trust.queue import FileQueue
from artifact_trust.util import sha256_file, write_json


def _statement(subjects: list[dict[str, object]]) -> dict[str, object]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {"buildDefinition": {}, "runDetails": {}},
    }


def _subject(name: str = "artifact.tar.gz", digest: str = "0" * 64) -> dict[str, object]:
    return {"name": name, "digest": {"sha256": digest}}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"_type": "unexpected"}), "statement type"),
        (lambda value: value.update({"predicate": None}), "predicate must"),
        (
            lambda value: value.update({"predicate": {"buildDefinition": [], "runDetails": {}}}),
            "predicate is incomplete",
        ),
        (lambda value: value.update({"subject": []}), "contain subjects"),
        (lambda value: value.update({"subject": [None]}), "malformed provenance subject"),
        (
            lambda value: value.update({"subject": [{"name": "", "digest": {}}]}),
            "malformed provenance subject",
        ),
        (
            lambda value: value.update({"subject": [_subject(digest="A" * 64)]}),
            "requires a SHA-256",
        ),
        (
            lambda value: value.update({"subject": [_subject(), _subject()]}),
            "duplicate provenance subject",
        ),
    ],
)
def test_subject_validation_fails_closed(
    mutation: Callable[[dict[str, object]], None], message: str
) -> None:
    statement = _statement([_subject()])
    mutation(statement)
    with pytest.raises(ValueError, match=message):
        subject_digests(statement)


def test_statement_builder_rejects_ambiguous_or_invalid_subjects(tmp_path: Path) -> None:
    source = MaterializedSource(
        root=tmp_path,
        kind="fixture",
        canonical_location="fixture:safe-app",
        commit=None,
        digest_sha256="1" * 64,
        file_count=0,
        total_size_bytes=0,
        pinned=True,
    )
    analysis = ManifestAnalysis(manifests=(), components=(), edges=())
    with pytest.raises(ValueError, match="provided separately"):
        build_statement(
            source,
            analysis,
            "0" * 64,
            "report",
            0,
            {"artifact.tar.gz": "2" * 64},
        )
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        build_statement(source, analysis, "A" * 64, "report", 0)


def test_envelope_subject_decoder_rejects_non_object_payload() -> None:
    with pytest.raises(ValueError, match="malformed DSSE"):
        envelope_subject_digests({})
    envelope = {"payload": base64.b64encode(b"[]").decode("ascii")}
    with pytest.raises(ValueError, match="object"):
        envelope_subject_digests(envelope)


def test_closed_set_verifier_rejects_missing_root_and_unsafe_subject(
    settings: Settings, tmp_path: Path
) -> None:
    private_key = load_private_key(settings.private_key_path)  # type: ignore[arg-type]
    public_key = load_public_key(settings.public_key_path)  # type: ignore[arg-type]
    exact_subjects = [_subject(name) for name in EVIDENCE_SUBJECTS]
    envelope = sign_statement(_statement(exact_subjects), private_key)
    missing = verify_evidence_directory(envelope, public_key, tmp_path / "missing")
    assert missing.signature_valid is True
    assert missing.provenance_valid is True
    assert missing.evidence_digests_valid is False
    assert missing.error == "verification failed: FileNotFoundError"

    unsafe = sign_statement(_statement([_subject("../escape")]), private_key)
    rejected = verify_evidence_directory(
        unsafe,
        public_key,
        tmp_path,
        expected_subjects=("../escape",),
    )
    assert rejected.signature_valid is True
    assert rejected.provenance_valid is True
    assert rejected.error == "verification failed: ValueError"


def test_closed_set_verifier_rejects_symlinked_evidence(settings: Settings, tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    root.mkdir()
    for name in EVIDENCE_SUBJECTS:
        (root / name).write_bytes(name.encode())
    target = tmp_path / "outside-report"
    target.write_bytes(b"outside")
    (root / "report.html").unlink()
    (root / "report.html").symlink_to(target)
    digests = {
        name: sha256_file(target if name == "report.html" else root / name)
        for name in EVIDENCE_SUBJECTS
    }
    envelope = sign_statement(
        _statement([_subject(name, digest) for name, digest in sorted(digests.items())]),
        load_private_key(settings.private_key_path),  # type: ignore[arg-type]
    )
    result = verify_evidence_directory(
        envelope,
        load_public_key(settings.public_key_path),  # type: ignore[arg-type]
        root,
    )
    assert result.signature_valid is True
    assert result.artifact_digest_valid is True
    assert result.evidence_digests_valid is False
    assert result.error == "signed evidence digest mismatch: report.html"


def _resign_evidence(output: Path, settings: Settings) -> None:
    envelope = json.loads((output / "provenance.dsse.json").read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    for subject in statement["subject"]:
        name = subject["name"]
        subject["digest"]["sha256"] = sha256_file(output / name)
    signed = sign_statement(
        statement,
        load_private_key(settings.private_key_path),  # type: ignore[arg-type]
    )
    write_json(output / "provenance.dsse.json", signed)


def test_queue_rejects_validly_signed_but_inconsistent_control_documents(
    settings: Settings,
) -> None:
    queue = FileQueue(settings)
    baseline = settings.work_root / "baseline"
    run_pipeline(SourceSpec(kind="fixture", location="safe-app"), baseline, settings, "fallback")

    mutations = (
        lambda decision: [],
        lambda decision: {**decision, "report_id": "different"},
        lambda decision: {**decision, "policy": {**decision["policy"], "reasons": ["changed"]}},
        lambda decision: {**decision, "risk": {**decision["risk"], "score": 99}},
        lambda decision: {
            **decision,
            "policy_input": {**decision["policy_input"], "secrets": 1},
        },
    )
    for mutate in mutations:
        queued = queue.enqueue(
            JobRequest(
                source=SourceSpec(kind="fixture", location="safe-app"),
                policy_engine="fallback",
            )
        )
        claimed = queue.claim()
        assert claimed is not None and claimed.id == queued.id
        output = settings.work_root / "results" / queued.id
        output.parent.mkdir(exist_ok=True)
        shutil.copytree(baseline, output)
        decision_path = output / "decision.json"
        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        write_json(decision_path, mutate(decision))
        _resign_evidence(output, settings)
        queue.complete(claimed, output / "report.json")
        with pytest.raises(JobError, match="documents are inconsistent"):
            queue.result(queued.id)
