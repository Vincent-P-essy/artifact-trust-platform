"""Typed contracts shared by the CLI, API, worker, and report renderer."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Decision(StrEnum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceSpec(FrozenModel):
    kind: Literal["local", "git", "fixture"]
    location: str
    commit: str | None = None

    @model_validator(mode="after")
    def require_git_commit(self) -> SourceSpec:
        if self.kind == "git" and not self.commit:
            raise ValueError("git sources require a pinned commit")
        if self.kind != "git" and self.commit is not None:
            raise ValueError("commit is only valid for git sources")
        return self


class SandboxPolicy(FrozenModel):
    network_enabled: bool = False
    command_execution: Literal["disabled", "git-fetch-only"] = "disabled"
    cpu_seconds: int = Field(default=30, ge=1, le=600)
    memory_mb: int = Field(default=512, ge=128, le=4096)
    max_files: int = Field(default=10_000, ge=1, le=100_000)
    max_file_size_bytes: int = Field(default=5_000_000, ge=1024, le=100_000_000)
    max_total_size_bytes: int = Field(default=100_000_000, ge=1024, le=2_000_000_000)
    pids: int = Field(default=64, ge=1, le=512)


class MaterializedSource(FrozenModel):
    root: Path
    kind: Literal["local", "git", "fixture"]
    canonical_location: str
    commit: str | None
    digest_sha256: str
    file_count: int
    total_size_bytes: int
    pinned: bool


class Component(FrozenModel):
    bom_ref: str
    name: str
    version: str
    ecosystem: Literal["npm", "pypi"]
    purl: str
    scope: Literal["required", "development", "optional"] = "required"
    direct: bool = False
    licenses: tuple[str, ...] = ()
    source_manifest: str


class DependencyEdge(FrozenModel):
    source: str
    target: str


class ManifestAnalysis(FrozenModel):
    manifests: tuple[str, ...]
    components: tuple[Component, ...]
    edges: tuple[DependencyEdge, ...]
    unpinned_dependencies: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class Finding(FrozenModel):
    id: str
    category: Literal["secret", "license", "vulnerability", "manifest"]
    severity: Severity
    title: str
    subject: str
    evidence: str
    remediation: str
    advisory: str | None = None

    @field_validator("evidence")
    @classmethod
    def reject_multiline_evidence(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("finding evidence must be a redacted single line")
        return value


class PolicyInput(FrozenModel):
    source_pinned: bool
    signature_valid: bool
    provenance_valid: bool
    artifact_digest_valid: bool
    evidence_digests_valid: bool
    secrets: int = Field(ge=0)
    critical_vulnerabilities: int = Field(ge=0)
    high_vulnerabilities: int = Field(ge=0)
    medium_vulnerabilities: int = Field(ge=0)
    disallowed_licenses: int = Field(ge=0)
    unknown_licenses: int = Field(ge=0)
    unpinned_dependencies: int = Field(ge=0)
    manifest_coverage_gaps: int = Field(default=0, ge=0)
    manifest_integrity_errors: int = Field(default=0, ge=0)


class PolicyResult(FrozenModel):
    decision: Decision
    reasons: tuple[str, ...]
    engine: Literal["fallback", "opa"]
    policy_version: str


class VerificationResult(FrozenModel):
    signature_valid: bool
    artifact_digest_valid: bool
    key_id: str
    subject_digest: str
    provenance_valid: bool
    evidence_digests_valid: bool
    error: str | None = None


class RiskAssessment(FrozenModel):
    score: int = Field(ge=0, le=100)
    grade: Literal["A", "B", "C", "D", "F"]
    deductions: tuple[str, ...]


class PipelineReport(FrozenModel):
    schema_version: str
    report_id: str
    source: dict[str, Any]
    artifact: dict[str, Any]
    manifests: ManifestAnalysis
    findings: tuple[Finding, ...]
    verification: VerificationResult
    risk: RiskAssessment
    policy: PolicyResult
    sandbox: SandboxPolicy
    outputs: dict[str, str]


class JobRequest(FrozenModel):
    source: SourceSpec
    policy_engine: Literal["fallback", "opa", "auto"] = "auto"

    @model_validator(mode="after")
    def api_source_restrictions(self) -> JobRequest:
        if self.source.kind == "local":
            raise ValueError("the API accepts named fixtures or pinned HTTPS Git sources only")
        return self


class JobRecord(FrozenModel):
    id: str
    state: Literal["pending", "running", "completed", "failed"]
    request: JobRequest
    created_at: str
    updated_at: str
    result_path: str | None = None
    error_code: str | None = None
    error_message: str | None = None
