"""Domain errors exposed with stable error codes."""


class ArtifactTrustError(Exception):
    """Base class for expected, user-facing failures."""

    code = "artifact_trust_error"


class SourceValidationError(ArtifactTrustError):
    code = "source_validation_error"


class SourceLimitError(ArtifactTrustError):
    code = "source_limit_error"


class SignatureVerificationError(ArtifactTrustError):
    code = "signature_verification_error"


class PolicyEvaluationError(ArtifactTrustError):
    code = "policy_evaluation_error"


class JobError(ArtifactTrustError):
    code = "job_error"
