from __future__ import annotations

import json
from pathlib import Path

import pytest

from artifact_trust.attack import run_tamper_scenario
from artifact_trust.benchmark import benchmark_pipeline
from artifact_trust.config import Settings
from artifact_trust.models import Decision, SourceSpec
from artifact_trust.pipeline import run_pipeline
from artifact_trust.provenance import (
    EVIDENCE_SUBJECTS,
    envelope_subject_digests,
    load_public_key,
    verify_evidence_directory,
)

DETERMINISTIC_OUTPUTS = (
    "artifact.tar.gz",
    "decision.json",
    "dependency-graph.json",
    "findings.json",
    "policy-input.json",
    "provenance.dsse.json",
    "report.html",
    "report.json",
    "sbom.cdx.json",
    "verification-key.pem",
)


@pytest.mark.integration
def test_safe_pipeline_matches_golden_and_is_byte_reproducible(
    settings: Settings, tmp_path: Path
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    spec = SourceSpec(kind="fixture", location="safe-app")
    first_report = run_pipeline(spec, first, settings, "fallback")
    second_report = run_pipeline(spec, second, settings, "fallback")
    for name in DETERMINISTIC_OUTPUTS:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name
    summary = {
        "component_count": len(first_report.manifests.components),
        "decision": first_report.policy.decision.value,
        "edge_count": len(first_report.manifests.edges),
        "finding_count": len(first_report.findings),
        "manifests": list(first_report.manifests.manifests),
        "transitive_component": next(
            item.name for item in first_report.manifests.components if not item.direct
        ),
    }
    golden = json.loads(
        (Path(__file__).parent / "golden" / "safe-summary.json").read_text(encoding="utf-8")
    )
    assert summary == golden
    assert first_report.risk.score == 100
    assert first_report.risk.grade == "A"
    assert second_report.report_id == first_report.report_id
    envelope = json.loads((first / "provenance.dsse.json").read_text(encoding="utf-8"))
    assert tuple(sorted(envelope_subject_digests(envelope))) == tuple(sorted(EVIDENCE_SUBJECTS))
    verification = verify_evidence_directory(
        envelope, load_public_key(first / "verification-key.pem"), first
    )
    assert verification.signature_valid
    assert verification.provenance_valid
    assert verification.evidence_digests_valid


@pytest.mark.parametrize(
    ("fixture", "decision"),
    [
        ("safe-app", Decision.ALLOW),
        ("vulnerable-app", Decision.QUARANTINE),
        ("rejected-app", Decision.REJECT),
        ("unpinned-app", Decision.REJECT),
    ],
)
def test_fixture_policy_matrix(
    settings: Settings, tmp_path: Path, fixture: str, decision: Decision
) -> None:
    report = run_pipeline(
        SourceSpec(kind="fixture", location=fixture), tmp_path / fixture, settings, "fallback"
    )
    assert report.policy.decision == decision
    matrix = json.loads(
        (Path(__file__).parent / "golden" / "policy-matrix.json").read_text(encoding="utf-8")
    )
    assert {
        "decision": report.policy.decision.value,
        "finding_count": len(report.findings),
        "risk_score": report.risk.score,
    } == matrix[fixture]


@pytest.mark.e2e
def test_controlled_tamper_scenario_is_blocked(settings: Settings, tmp_path: Path) -> None:
    result = run_tamper_scenario(
        SourceSpec(kind="fixture", location="safe-app"), tmp_path / "attack", settings
    )
    assert result["signature_valid"] is True
    assert result["artifact_digest_valid"] is False
    assert result["tampered_decision"] == "REJECT"
    assert result["blocked"] is True


def test_benchmark_reports_measured_percentiles(settings: Settings) -> None:
    result = benchmark_pipeline(
        SourceSpec(kind="fixture", location="safe-app"), settings, iterations=3, warmups=1
    )
    assert result["p50_ms"] > 0
    assert result["p95_ms"] >= result["p50_ms"]
    assert result["decision"] == "ALLOW"
