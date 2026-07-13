"""Deterministic policy engine with an optional OPA adapter."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from artifact_trust.config import PACKAGE_ROOT
from artifact_trust.errors import PolicyEvaluationError
from artifact_trust.models import (
    Decision,
    Finding,
    ManifestAnalysis,
    PolicyInput,
    PolicyResult,
    Severity,
    VerificationResult,
)
from artifact_trust.util import write_json

POLICY_VERSION = "2026-07-13.1"


def make_policy_input(
    findings: tuple[Finding, ...],
    analysis: ManifestAnalysis,
    verification: VerificationResult,
    source_pinned: bool,
) -> PolicyInput:
    vulnerabilities = [finding for finding in findings if finding.category == "vulnerability"]
    licenses = [finding for finding in findings if finding.category == "license"]
    return PolicyInput(
        source_pinned=source_pinned,
        signature_valid=verification.signature_valid,
        provenance_valid=verification.provenance_valid,
        artifact_digest_valid=verification.artifact_digest_valid,
        evidence_digests_valid=verification.evidence_digests_valid,
        secrets=sum(finding.category == "secret" for finding in findings),
        critical_vulnerabilities=sum(
            finding.severity == Severity.CRITICAL for finding in vulnerabilities
        ),
        high_vulnerabilities=sum(finding.severity == Severity.HIGH for finding in vulnerabilities),
        medium_vulnerabilities=sum(
            finding.severity == Severity.MEDIUM for finding in vulnerabilities
        ),
        disallowed_licenses=sum(finding.severity == Severity.HIGH for finding in licenses),
        unknown_licenses=sum(finding.severity == Severity.MEDIUM for finding in licenses),
        unpinned_dependencies=len(analysis.unpinned_dependencies),
        manifest_coverage_gaps=sum(
            finding.category == "manifest" and finding.severity == Severity.MEDIUM
            for finding in findings
        ),
        manifest_integrity_errors=sum(
            finding.category == "manifest"
            and finding.severity in {Severity.HIGH, Severity.CRITICAL}
            for finding in findings
        ),
    )


def evaluate_fallback(policy_input: PolicyInput) -> PolicyResult:
    reject_reasons: list[str] = []
    quarantine_reasons: list[str] = []
    if not policy_input.source_pinned:
        reject_reasons.append("source is not pinned")
    if not policy_input.signature_valid:
        reject_reasons.append("provenance signature is invalid")
    if not policy_input.provenance_valid:
        reject_reasons.append("provenance statement is invalid")
    if not policy_input.artifact_digest_valid:
        reject_reasons.append("artifact digest does not match provenance")
    if not policy_input.evidence_digests_valid:
        reject_reasons.append("signed evidence digests do not match")
    if policy_input.secrets:
        reject_reasons.append("potential secrets detected")
    if policy_input.critical_vulnerabilities:
        reject_reasons.append("critical vulnerabilities detected")
    if policy_input.disallowed_licenses:
        reject_reasons.append("disallowed licenses detected")
    if policy_input.unpinned_dependencies:
        reject_reasons.append("dependencies are not exactly pinned")
    if policy_input.manifest_integrity_errors:
        reject_reasons.append("dependency manifest integrity is incomplete")
    if policy_input.high_vulnerabilities:
        quarantine_reasons.append("high vulnerabilities require review")
    if policy_input.medium_vulnerabilities:
        quarantine_reasons.append("medium vulnerabilities require review")
    if policy_input.unknown_licenses:
        quarantine_reasons.append("unknown licenses require review")
    if policy_input.manifest_coverage_gaps:
        quarantine_reasons.append("dependency manifest coverage requires review")
    if reject_reasons:
        decision = Decision.REJECT
        reasons = tuple(sorted(reject_reasons))
    elif quarantine_reasons:
        decision = Decision.QUARANTINE
        reasons = tuple(sorted(quarantine_reasons))
    else:
        decision = Decision.ALLOW
        reasons = ("all mandatory controls passed",)
    return PolicyResult(
        decision=decision,
        reasons=reasons,
        engine="fallback",
        policy_version=POLICY_VERSION,
    )


def evaluate_opa(policy_input: PolicyInput, opa_binary: str = "opa") -> PolicyResult:
    executable = shutil.which(opa_binary)
    if executable is None:
        raise PolicyEvaluationError("OPA executable is unavailable")
    policy_path = PACKAGE_ROOT / "data" / "policy.rego"
    with tempfile.TemporaryDirectory(prefix="artifact-trust-opa-") as temporary:
        input_path = Path(temporary) / "input.json"
        write_json(input_path, policy_input.model_dump(mode="json"))
        try:
            result = subprocess.run(
                [
                    executable,
                    "eval",
                    "--format=json",
                    "--fail",
                    "--data",
                    str(policy_path),
                    "--input",
                    str(input_path),
                    "data.artifacttrust.decision",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise PolicyEvaluationError("OPA evaluation failed") from exc
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise PolicyEvaluationError("OPA returned malformed JSON") from exc
    try:
        value = payload["result"][0]["expressions"][0]["value"]
        decision = Decision(value["decision"])
        raw_reasons = value["reasons"]
        if (
            not isinstance(raw_reasons, list)
            or not raw_reasons
            or not all(isinstance(item, str) for item in raw_reasons)
        ):
            raise TypeError("invalid policy reasons")
        reasons = tuple(raw_reasons)
        version = str(value["policy_version"])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise PolicyEvaluationError("OPA returned an invalid decision document") from exc
    if version != POLICY_VERSION or reasons != tuple(sorted(reasons)):
        raise PolicyEvaluationError("OPA returned an incompatible decision document")
    return PolicyResult(decision=decision, reasons=reasons, engine="opa", policy_version=version)


def evaluate_policy(
    policy_input: PolicyInput, engine: Literal["fallback", "opa", "auto"] = "auto"
) -> PolicyResult:
    if engine == "fallback":
        return evaluate_fallback(policy_input)
    fallback = evaluate_fallback(policy_input)

    def evaluate_with_parity() -> PolicyResult:
        opa = evaluate_opa(policy_input)
        if (
            opa.decision != fallback.decision
            or opa.reasons != fallback.reasons
            or opa.policy_version != fallback.policy_version
        ):
            raise PolicyEvaluationError("OPA and fallback policy decisions diverged")
        return opa

    if engine == "opa":
        return evaluate_with_parity()
    try:
        return evaluate_with_parity()
    except PolicyEvaluationError:
        return fallback
