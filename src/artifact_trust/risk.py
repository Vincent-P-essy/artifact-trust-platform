"""Transparent deterministic repository risk score."""

from __future__ import annotations

from typing import Literal

from artifact_trust.models import Finding, RiskAssessment, Severity, VerificationResult


def assess_risk(
    findings: tuple[Finding, ...], verification: VerificationResult, source_pinned: bool
) -> RiskAssessment:
    deductions: list[tuple[str, int]] = []
    if not source_pinned:
        deductions.append(("source is not pinned", 30))
    if not verification.signature_valid or not verification.artifact_digest_valid:
        deductions.append(("artifact integrity evidence is invalid", 100))
    weights = {
        ("secret", Severity.CRITICAL): 40,
        ("vulnerability", Severity.CRITICAL): 30,
        ("vulnerability", Severity.HIGH): 15,
        ("vulnerability", Severity.MEDIUM): 5,
        ("license", Severity.HIGH): 20,
        ("license", Severity.MEDIUM): 5,
        ("manifest", Severity.HIGH): 20,
        ("manifest", Severity.MEDIUM): 10,
    }
    for finding in findings:
        weight = weights.get((finding.category, finding.severity), 0)
        if weight:
            deductions.append((f"{finding.id}: {finding.title}", weight))
    score = max(0, 100 - sum(weight for _, weight in deductions))
    grade: Literal["A", "B", "C", "D", "F"]
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return RiskAssessment(
        score=score,
        grade=grade,
        deductions=tuple(reason for reason, _ in deductions),
    )
