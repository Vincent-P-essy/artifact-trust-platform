"""Controlled artifact tampering scenario."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Literal

from artifact_trust.config import Settings
from artifact_trust.models import Decision, SourceSpec
from artifact_trust.pipeline import run_pipeline
from artifact_trust.policy import evaluate_policy, make_policy_input
from artifact_trust.provenance import load_public_key, verify_envelope
from artifact_trust.util import write_json


def run_tamper_scenario(
    source_spec: SourceSpec,
    output: Path,
    settings: Settings,
    policy_engine: Literal["fallback", "opa", "auto"] = "fallback",
) -> dict[str, Any]:
    baseline = output / "baseline"
    report = run_pipeline(source_spec, baseline, settings, policy_engine)
    tampered = output / "tampered-artifact.tar.gz"
    shutil.copyfile(baseline / "artifact.tar.gz", tampered)
    with tampered.open("ab") as handle:
        handle.write(b"\nARTIFACT-TRUST-CONTROLLED-TAMPER\n")
    envelope = json.loads((baseline / "provenance.dsse.json").read_text(encoding="utf-8"))
    verification = verify_envelope(
        envelope, load_public_key(baseline / "verification-key.pem"), tampered
    )
    policy_input = make_policy_input(
        report.findings,
        report.manifests,
        verification,
        bool(report.source["pinned"]),
    )
    policy = evaluate_policy(policy_input, policy_engine)
    result = {
        "scenario": "artifact-byte-tampering",
        "baseline_decision": report.policy.decision.value,
        "signature_valid": verification.signature_valid,
        "artifact_digest_valid": verification.artifact_digest_valid,
        "tampered_decision": policy.decision.value,
        "blocked": policy.decision == Decision.REJECT,
        "reasons": list(policy.reasons),
    }
    write_json(output / "attack-result.json", result)
    return result
