"""End-to-end evidence pipeline."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from artifact_trust import __version__
from artifact_trust.artifact import build_source_artifact
from artifact_trust.config import Settings
from artifact_trust.errors import SourceValidationError
from artifact_trust.manifests import analyze_manifests
from artifact_trust.models import PipelineReport, SourceSpec, VerificationResult
from artifact_trust.policy import evaluate_policy, make_policy_input
from artifact_trust.provenance import (
    EVIDENCE_SUBJECTS,
    build_statement,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_id,
    sign_statement,
    verify_evidence_directory,
)
from artifact_trust.reporting import render_html
from artifact_trust.risk import assess_risk
from artifact_trust.sbom import build_cyclonedx, build_dependency_graph
from artifact_trust.scanners import run_offline_scans
from artifact_trust.source import materialize_source, remove_materialized_source
from artifact_trust.util import canonical_json_bytes, sha256_bytes, sha256_file, write_json


def ensure_signing_key(settings: Settings) -> tuple[Path, Path]:
    settings.ensure_directories()
    if settings.private_key_path:
        private_path = settings.private_key_path
        public_path = settings.public_key_path
        if public_path is None:
            public_path = settings.work_root / "keys" / "derived-public.pem"
        if not private_path.exists() and not public_path.exists():
            generate_keypair(private_path, public_path)
        elif not private_path.exists():
            raise FileNotFoundError("configured signing key is missing")
        elif not public_path.exists():
            public_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            key = load_private_key(private_path)
            public_path.write_bytes(
                key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            public_path.chmod(0o644)
        return private_path, public_path
    if settings.public_key_path is not None:
        raise FileNotFoundError("a signing key is required to produce evidence")
    key_root = settings.work_root / "keys"
    key_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path = key_root / "signing-key.pem"
    public_path = key_root / "verification-key.pem"
    if not private_path.exists() and not public_path.exists():
        generate_keypair(private_path, public_path)
    if not private_path.exists() or not public_path.exists():
        raise FileNotFoundError("incomplete signing keypair")
    return private_path, public_path


def _validate_keypair(private_key: Ed25519PrivateKey, public_path: Path) -> None:
    public_key = load_public_key(public_path)
    if public_key_id(private_key.public_key()) != public_key_id(public_key):
        raise ValueError("configured signing and verification keys do not match")


def _prepare_stage(output: Path) -> Path:
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if any(output.iterdir()):
            raise FileExistsError(f"output directory is not empty: {output}")
        output.rmdir()
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    stage.chmod(0o750)
    return stage


def run_pipeline(
    source_spec: SourceSpec,
    output: Path,
    settings: Settings,
    policy_engine: Literal["fallback", "opa", "auto"] = "auto",
) -> PipelineReport:
    settings.ensure_directories()
    source = materialize_source(source_spec, settings)
    stage: Path | None = None
    try:
        output_resolved = output.resolve()
        if output_resolved == source.root or output_resolved.is_relative_to(source.root):
            raise SourceValidationError("output directory must be outside the source tree")
        stage = _prepare_stage(output_resolved)
        artifact_path = stage / "artifact.tar.gz"
        artifact_digest, artifact_size = build_source_artifact(
            source.root, artifact_path, settings.sandbox
        )
        analysis = analyze_manifests(source.root, settings.sandbox)
        findings = run_offline_scans(source.root, analysis, settings.sandbox)
        report_seed = {
            "tool_version": __version__,
            "source_digest": source.digest_sha256,
            "artifact_digest": artifact_digest,
            "components": [component.bom_ref for component in analysis.components],
            "findings": [finding.id for finding in findings],
        }
        report_id = f"atr-{sha256_bytes(canonical_json_bytes(report_seed))[:24]}"
        private_path, public_path = ensure_signing_key(settings)
        private_key = load_private_key(private_path)
        _validate_keypair(private_key, public_path)
        key_id = public_key_id(private_key.public_key())
        verification = VerificationResult(
            signature_valid=True,
            provenance_valid=True,
            artifact_digest_valid=True,
            evidence_digests_valid=True,
            key_id=key_id,
            subject_digest=artifact_digest,
        )
        risk = assess_risk(findings, verification, source.pinned)
        policy_input = make_policy_input(findings, analysis, verification, source.pinned)
        policy_result = evaluate_policy(policy_input, policy_engine)

        source_name = source.canonical_location.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
        write_json(
            stage / "sbom.cdx.json",
            build_cyclonedx(analysis, source.digest_sha256, source_name),
        )
        write_json(stage / "dependency-graph.json", build_dependency_graph(analysis))
        write_json(stage / "findings.json", [item.model_dump(mode="json") for item in findings])
        write_json(stage / "policy-input.json", policy_input.model_dump(mode="json"))
        shutil.copyfile(public_path, stage / "verification-key.pem")
        (stage / "verification-key.pem").chmod(0o644)

        outputs = {
            "artifact": "artifact.tar.gz",
            "dependency_graph": "dependency-graph.json",
            "decision": "decision.json",
            "findings": "findings.json",
            "html_report": "report.html",
            "json_report": "report.json",
            "policy_input": "policy-input.json",
            "provenance": "provenance.dsse.json",
            "sbom": "sbom.cdx.json",
            "verification_key": "verification-key.pem",
        }
        write_json(
            stage / "decision.json",
            {
                "schema_version": "1.0",
                "report_id": report_id,
                "policy_input": policy_input.model_dump(mode="json"),
                "policy": policy_result.model_dump(mode="json"),
                "risk": risk.model_dump(mode="json"),
            },
        )
        report = PipelineReport(
            schema_version="1.0",
            report_id=report_id,
            source={
                "kind": source.kind,
                "location": source.canonical_location,
                "commit": source.commit,
                "digest_sha256": source.digest_sha256,
                "file_count": source.file_count,
                "total_size_bytes": source.total_size_bytes,
                "pinned": source.pinned,
            },
            artifact={
                "name": "artifact.tar.gz",
                "digest_sha256": artifact_digest,
                "size_bytes": artifact_size,
                "repository_code_executed": False,
            },
            manifests=analysis,
            findings=findings,
            verification=verification,
            risk=risk,
            policy=policy_result,
            sandbox=settings.sandbox,
            outputs=outputs,
        )
        write_json(stage / "report.json", report.model_dump(mode="json"))
        render_html(report, stage / "report.html")
        evidence_digests = {
            name: sha256_file(stage / name)
            for name in EVIDENCE_SUBJECTS
            if name != "artifact.tar.gz"
        }
        statement = build_statement(
            source,
            analysis,
            artifact_digest,
            report_id,
            settings.source_date_epoch,
            evidence_digests,
        )
        envelope = sign_statement(statement, private_key)
        write_json(stage / "provenance.dsse.json", envelope)
        final_verification = verify_evidence_directory(
            envelope, load_public_key(public_path), stage
        )
        if final_verification != verification:
            raise ValueError(
                "generated evidence failed closed-set signature and digest verification"
            )
        os.replace(stage, output_resolved)
        return report
    except Exception:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise
    finally:
        remove_materialized_source(source, settings)


def load_report(path: Path) -> PipelineReport:
    return PipelineReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
