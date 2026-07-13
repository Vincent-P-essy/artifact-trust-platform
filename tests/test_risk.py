from artifact_trust.models import Finding, Severity, VerificationResult
from artifact_trust.risk import assess_risk


def test_risk_score_is_transparent_and_bounded() -> None:
    verification = VerificationResult(
        signature_valid=True,
        artifact_digest_valid=True,
        key_id="sha256:key",
        subject_digest="a" * 64,
    )
    finding = Finding(
        id="ATF-VUL-TEST",
        category="vulnerability",
        severity=Severity.HIGH,
        title="Known risk",
        subject="pkg:npm/example@1",
        evidence="advisory:test",
        remediation="Upgrade",
    )
    assessment = assess_risk((finding,), verification, True)
    assert assessment.score == 85
    assert assessment.grade == "B"
    invalid = verification.model_copy(update={"artifact_digest_valid": False})
    assert assess_risk((finding,), invalid, False).score == 0
