"""Deterministic in-toto statement creation and Ed25519 DSSE signing."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from artifact_trust import __version__
from artifact_trust.models import ManifestAnalysis, MaterializedSource, VerificationResult
from artifact_trust.util import canonical_json_bytes, sha256_bytes, sha256_file

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_SUBJECTS = (
    "artifact.tar.gz",
    "decision.json",
    "dependency-graph.json",
    "findings.json",
    "policy-input.json",
    "report.html",
    "report.json",
    "sbom.cdx.json",
)


def generate_keypair(private_path: Path, public_path: Path) -> str:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("refusing to overwrite an existing signing key")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_path.chmod(0o644)
    return public_key_id(public_key)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("signing key must be Ed25519")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("verification key must be Ed25519")
    return key


def public_key_id(key: Ed25519PublicKey) -> str:
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{sha256_bytes(der)}"


def build_statement(
    source: MaterializedSource,
    analysis: ManifestAnalysis,
    artifact_digest: str,
    report_id: str,
    source_date_epoch: int,
    evidence_digests: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    timestamp = datetime.fromtimestamp(source_date_epoch, tz=UTC).isoformat().replace("+00:00", "Z")
    dependencies = [{"uri": component.purl} for component in analysis.components]
    supplied = dict(evidence_digests or {})
    if "artifact.tar.gz" in supplied:
        raise ValueError("artifact subject must be provided separately")
    subjects = {"artifact.tar.gz": artifact_digest, **supplied}
    if any(not SHA256_RE.fullmatch(digest) for digest in subjects.values()):
        raise ValueError("evidence subjects require lowercase SHA-256 digests")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": name, "digest": {"sha256": digest}}
            for name, digest in sorted(subjects.items())
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://artifact-trust.dev/build/source-bundle/v1",
                "externalParameters": {
                    "source": source.canonical_location,
                    "commit": source.commit,
                    "sourceAcquisitionNetworkEnabled": source.kind == "git",
                    "bundleBuildNetworkEnabled": False,
                    "repositoryCodeExecuted": False,
                },
                "internalParameters": {"sourceDigest": source.digest_sha256},
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {"id": f"artifact-trust-platform/{__version__}"},
                "metadata": {
                    "invocationId": report_id,
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
            },
        },
    }


def _pae(payload_type: str, payload: bytes) -> bytes:
    encoded_type = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(encoded_type), encoded_type, len(payload), payload)


def sign_statement(statement: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = canonical_json_bytes(statement)
    key_id = public_key_id(private_key.public_key())
    signature = private_key.sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
    }


def _verify_signature(
    envelope: dict[str, Any], public_key: Ed25519PublicKey, key_id: str
) -> dict[str, Any]:
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("unexpected payload type")
    payload_encoded = envelope.get("payload")
    signatures = envelope.get("signatures")
    if (
        not isinstance(payload_encoded, str)
        or not isinstance(signatures, list)
        or len(signatures) != 1
    ):
        raise ValueError("malformed DSSE envelope")
    entry = signatures[0]
    if not isinstance(entry, dict) or entry.get("keyid") != key_id:
        raise ValueError("signing key identifier mismatch")
    payload = base64.b64decode(payload_encoded, validate=True)
    signature = base64.b64decode(str(entry.get("sig", "")), validate=True)
    public_key.verify(signature, _pae(PAYLOAD_TYPE, payload))
    statement = json.loads(payload)
    if not isinstance(statement, dict):
        raise ValueError("signed payload must be an object")
    return statement


def subject_digests(statement: dict[str, Any]) -> dict[str, str]:
    """Validate and return the unique SHA-256 subjects from an in-toto statement."""
    if statement.get("_type") != STATEMENT_TYPE:
        raise ValueError("unexpected in-toto statement type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError("unexpected provenance predicate type")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ValueError("provenance predicate must be an object")
    if not isinstance(predicate.get("buildDefinition"), dict) or not isinstance(
        predicate.get("runDetails"), dict
    ):
        raise ValueError("provenance predicate is incomplete")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("provenance must contain subjects")
    digests: dict[str, str] = {}
    for subject in subjects:
        if not isinstance(subject, dict):
            raise ValueError("malformed provenance subject")
        name = subject.get("name")
        digest_map = subject.get("digest")
        if not isinstance(name, str) or not name or not isinstance(digest_map, dict):
            raise ValueError("malformed provenance subject")
        digest = digest_map.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValueError("provenance subject requires a SHA-256 digest")
        if name in digests:
            raise ValueError("duplicate provenance subject")
        digests[name] = digest
    return digests


def envelope_subject_digests(envelope: dict[str, Any]) -> dict[str, str]:
    """Decode subjects after the caller has authenticated this exact envelope."""
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise ValueError("malformed DSSE envelope")
    statement = json.loads(base64.b64decode(payload, validate=True))
    if not isinstance(statement, dict):
        raise ValueError("signed payload must be an object")
    return subject_digests(statement)


def verify_envelope(
    envelope: dict[str, Any], public_key: Ed25519PublicKey, artifact_path: Path
) -> VerificationResult:
    """Verify DSSE semantics and the artifact subject.

    This compatibility helper verifies only ``artifact.tar.gz``. Control-plane reads use
    :func:`verify_evidence_directory`, which requires the closed evidence subject set.
    """
    key_id = public_key_id(public_key)
    subject_digest = ""
    signature_valid = False
    provenance_valid = False
    artifact_digest_valid = False
    evidence_digests_valid = False
    error: str | None = None
    try:
        statement = _verify_signature(envelope, public_key, key_id)
        signature_valid = True
        digests = subject_digests(statement)
        provenance_valid = True
        if "artifact.tar.gz" not in digests:
            raise ValueError("provenance has no artifact subject")
        subject_digest = digests["artifact.tar.gz"]
        artifact_digest_valid = sha256_file(artifact_path) == subject_digest
        evidence_digests_valid = artifact_digest_valid
        if not artifact_digest_valid:
            error = "artifact digest does not match signed provenance"
    except (
        InvalidSignature,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        binascii.Error,
    ) as exc:
        error = f"verification failed: {type(exc).__name__}"
    return VerificationResult(
        signature_valid=signature_valid,
        artifact_digest_valid=artifact_digest_valid,
        key_id=key_id,
        subject_digest=subject_digest,
        provenance_valid=provenance_valid,
        evidence_digests_valid=evidence_digests_valid,
        error=error,
    )


def verify_evidence_directory(
    envelope: dict[str, Any],
    public_key: Ed25519PublicKey,
    evidence_root: Path,
    expected_subjects: Sequence[str] = EVIDENCE_SUBJECTS,
) -> VerificationResult:
    """Verify the signature, provenance shape, exact subject set, and every evidence digest."""
    key_id = public_key_id(public_key)
    subject_digest = ""
    signature_valid = False
    provenance_valid = False
    artifact_digest_valid = False
    evidence_digests_valid = False
    error: str | None = None
    try:
        statement = _verify_signature(envelope, public_key, key_id)
        signature_valid = True
        digests = subject_digests(statement)
        provenance_valid = True
        expected = tuple(sorted(expected_subjects))
        if tuple(sorted(digests)) != expected:
            raise ValueError("signed evidence subject set is incomplete or unexpected")
        root = evidence_root.resolve(strict=True)
        mismatches: list[str] = []
        for name in expected:
            if Path(name).name != name:
                raise ValueError("invalid evidence subject name")
            path = root / name
            if path.is_symlink() or not path.is_file():
                mismatches.append(name)
                continue
            if sha256_file(path) != digests[name]:
                mismatches.append(name)
        subject_digest = digests["artifact.tar.gz"]
        artifact_digest_valid = "artifact.tar.gz" not in mismatches
        evidence_digests_valid = not mismatches
        if mismatches:
            error = "signed evidence digest mismatch: " + ", ".join(mismatches)
    except (
        InvalidSignature,
        ValueError,
        KeyError,
        TypeError,
        OSError,
        json.JSONDecodeError,
        binascii.Error,
    ) as exc:
        error = f"verification failed: {type(exc).__name__}"
    return VerificationResult(
        signature_valid=signature_valid,
        artifact_digest_valid=artifact_digest_valid,
        key_id=key_id,
        subject_digest=subject_digest,
        provenance_valid=provenance_valid,
        evidence_digests_valid=evidence_digests_valid,
        error=error,
    )
