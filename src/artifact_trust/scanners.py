"""Offline, reproducible secret, license, vulnerability, and manifest checks."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from artifact_trust.config import PACKAGE_ROOT
from artifact_trust.models import Finding, ManifestAnalysis, SandboxPolicy, Severity
from artifact_trust.util import iter_safe_files

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\b"
            r"\s*[:=]\s*[\"']?([A-Za-z0-9_./+=:-]{12,})"
        ),
    ),
)
TEXT_SAMPLE_BYTES = 8192
ALLOWED_LICENSES = frozenset(
    {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "Python-2.0"}
)
DENIED_LICENSE_TOKENS = frozenset({"AGPL", "GPL", "SSPL", "BUSL"})


def _finding_id(category: str, subject: str, discriminator: str) -> str:
    value = f"{category}\0{subject}\0{discriminator}".encode()
    return f"ATF-{category[:3].upper()}-{hashlib.sha256(value).hexdigest()[:12].upper()}"


def scan_secrets(root: Path, limits: SandboxPolicy) -> list[Finding]:
    findings: list[Finding] = []
    for relative, path, _ in iter_safe_files(root, limits):
        payload = path.read_bytes()
        if b"\0" in payload[:TEXT_SAMPLE_BYTES]:
            continue
        text = payload.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for kind, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if match is None:
                    continue
                secret = match.group(1) if match.lastindex else match.group(0)
                fingerprint = hashlib.sha256(
                    b"artifact-trust-secret-fingerprint-v1\0" + secret.encode("utf-8")
                ).hexdigest()[:16]
                subject = f"{relative}:{line_number}"
                findings.append(
                    Finding(
                        id=_finding_id("secret", subject, f"{kind}:{fingerprint}"),
                        category="secret",
                        severity=Severity.CRITICAL,
                        title=f"Potential {kind} secret",
                        subject=subject,
                        evidence=f"redacted sha256:{fingerprint}",
                        remediation="Revoke the credential, remove it from history, and use a secret manager",
                    )
                )
                break
    return sorted(findings, key=lambda item: (item.subject, item.id))


def _license_classification(license_name: str) -> str:
    normalized = license_name.strip()
    if normalized in ALLOWED_LICENSES:
        return "allowed"
    tokens = {item.upper() for item in re.split(r"[^A-Za-z0-9.-]+", normalized) if item}
    if any(any(token.startswith(denied) for denied in DENIED_LICENSE_TOKENS) for token in tokens):
        return "denied"
    return "unknown"


def scan_licenses(analysis: ManifestAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    for component in analysis.components:
        if not component.licenses:
            findings.append(
                Finding(
                    id=_finding_id("license", component.bom_ref, "unknown"),
                    category="license",
                    severity=Severity.MEDIUM,
                    title="Dependency license is unknown",
                    subject=component.bom_ref,
                    evidence="license:unknown",
                    remediation="Record and review a valid SPDX license identifier",
                )
            )
            continue
        for license_name in component.licenses:
            classification = _license_classification(license_name)
            if classification == "allowed":
                continue
            findings.append(
                Finding(
                    id=_finding_id("license", component.bom_ref, license_name),
                    category="license",
                    severity=Severity.HIGH if classification == "denied" else Severity.MEDIUM,
                    title=(
                        "Dependency license is disallowed"
                        if classification == "denied"
                        else "Dependency license needs review"
                    ),
                    subject=component.bom_ref,
                    evidence=f"license:{license_name[:80]}",
                    remediation="Replace the dependency or obtain an explicit policy exception",
                )
            )
    return sorted(findings, key=lambda item: (item.subject, item.evidence))


def load_advisories(path: Path | None = None) -> list[dict[str, Any]]:
    database = path or PACKAGE_ROOT / "data" / "advisories.json"
    payload = json.loads(database.read_text(encoding="utf-8"))
    advisories = payload.get("advisories")
    if not isinstance(advisories, list):
        raise ValueError("invalid advisory database")
    return [item for item in advisories if isinstance(item, dict)]


def scan_vulnerabilities(
    analysis: ManifestAnalysis, advisory_path: Path | None = None
) -> list[Finding]:
    advisories = load_advisories(advisory_path)
    findings: list[Finding] = []
    for component in analysis.components:
        for advisory in advisories:
            if advisory.get("ecosystem") != component.ecosystem:
                continue
            if str(advisory.get("package", "")).lower() != component.name.lower():
                continue
            try:
                affected = SpecifierSet(str(advisory["affected"]))
                version = Version(component.version)
            except (InvalidSpecifier, InvalidVersion, KeyError):
                continue
            if version not in affected:
                continue
            severity_value = str(advisory.get("severity", "medium")).lower()
            try:
                severity = Severity(severity_value)
            except ValueError:
                severity = Severity.MEDIUM
            advisory_id = str(advisory.get("id", "unknown"))
            findings.append(
                Finding(
                    id=_finding_id("vulnerability", component.bom_ref, advisory_id),
                    category="vulnerability",
                    severity=severity,
                    title=str(advisory.get("summary", "Known vulnerable dependency")),
                    subject=component.bom_ref,
                    evidence=f"advisory:{advisory_id};affected:{advisory.get('affected', 'unknown')}",
                    remediation=str(advisory.get("remediation", "Upgrade to a fixed version")),
                    advisory=advisory_id,
                )
            )
    return sorted(findings, key=lambda item: (item.subject, item.advisory or ""))


def scan_manifest_quality(analysis: ManifestAnalysis) -> list[Finding]:
    findings: list[Finding] = []
    for dependency in analysis.unpinned_dependencies:
        findings.append(
            Finding(
                id=_finding_id("manifest", dependency, "unpinned"),
                category="manifest",
                severity=Severity.HIGH,
                title="Dependency is not pinned exactly",
                subject=dependency,
                evidence="version:not-exactly-pinned",
                remediation="Resolve and commit an exact lockfile version",
            )
        )
    for warning in analysis.warnings:
        subject = " ".join(warning.replace("\x00", "").split())[:300]
        findings.append(
            Finding(
                id=_finding_id("manifest", subject, "integrity-gap"),
                category="manifest",
                severity=Severity.HIGH,
                title="Dependency manifest is incomplete or inconsistent",
                subject=subject,
                evidence="manifest:integrity-incomplete",
                remediation="Regenerate and commit a complete supported lockfile",
            )
        )
    if not analysis.manifests:
        findings.append(
            Finding(
                id=_finding_id("manifest", "source", "missing"),
                category="manifest",
                severity=Severity.MEDIUM,
                title="No supported dependency manifest found",
                subject="source",
                evidence="manifest:none-supported",
                remediation="Commit a supported lockfile or manifest",
            )
        )
    return sorted(findings, key=lambda item: item.id)


def run_offline_scans(
    root: Path, analysis: ManifestAnalysis, limits: SandboxPolicy
) -> tuple[Finding, ...]:
    findings = [
        *scan_secrets(root, limits),
        *scan_licenses(analysis),
        *scan_vulnerabilities(analysis),
        *scan_manifest_quality(analysis),
    ]
    return tuple(sorted(findings, key=lambda item: (item.category, item.severity, item.id)))
