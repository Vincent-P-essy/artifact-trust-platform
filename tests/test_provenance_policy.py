from __future__ import annotations

import json
from pathlib import Path

from artifact_trust.config import Settings
from artifact_trust.models import Decision, PolicyInput, SourceSpec
from artifact_trust.pipeline import run_pipeline
from artifact_trust.policy import evaluate_fallback, evaluate_policy
from artifact_trust.provenance import load_public_key, verify_envelope


def _policy_input(**updates: object) -> PolicyInput:
    values: dict[str, object] = {
        "source_pinned": True,
        "signature_valid": True,
        "provenance_valid": True,
        "artifact_digest_valid": True,
        "evidence_digests_valid": True,
        "secrets": 0,
        "critical_vulnerabilities": 0,
        "high_vulnerabilities": 0,
        "medium_vulnerabilities": 0,
        "disallowed_licenses": 0,
        "unknown_licenses": 0,
        "unpinned_dependencies": 0,
    }
    values.update(updates)
    return PolicyInput.model_validate(values)


def test_fallback_policy_has_three_outcomes() -> None:
    assert evaluate_fallback(_policy_input()).decision == Decision.ALLOW
    assert evaluate_fallback(_policy_input(high_vulnerabilities=1)).decision == Decision.QUARANTINE
    assert evaluate_fallback(_policy_input(secrets=1)).decision == Decision.REJECT
    assert evaluate_fallback(_policy_input(manifest_integrity_errors=1)).decision == Decision.REJECT


def test_auto_policy_falls_back_when_opa_is_missing() -> None:
    result = evaluate_policy(_policy_input(), "auto")
    assert result.engine == "fallback"
    assert result.decision == Decision.ALLOW


def test_signed_provenance_detects_artifact_tampering(settings: Settings, tmp_path: Path) -> None:
    output = tmp_path / "out"
    run_pipeline(
        source_spec=SourceSpec(kind="fixture", location="safe-app"),
        output=output,
        settings=settings,
        policy_engine="fallback",
    )
    envelope = json.loads((output / "provenance.dsse.json").read_text(encoding="utf-8"))
    artifact = output / "artifact.tar.gz"
    valid = verify_envelope(envelope, load_public_key(output / "verification-key.pem"), artifact)
    assert valid.signature_valid and valid.artifact_digest_valid
    with artifact.open("ab") as handle:
        handle.write(b"tamper")
    invalid = verify_envelope(envelope, load_public_key(output / "verification-key.pem"), artifact)
    assert invalid.signature_valid is True
    assert invalid.artifact_digest_valid is False
    assert "does not match" in (invalid.error or "")
