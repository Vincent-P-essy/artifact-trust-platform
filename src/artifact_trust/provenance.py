"""Deterministic in-toto statement creation and Ed25519 DSSE signing."""

from __future__ import annotations

import base64
import json
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
) -> dict[str, Any]:
    timestamp = datetime.fromtimestamp(source_date_epoch, tz=UTC).isoformat().replace("+00:00", "Z")
    dependencies = [{"uri": component.purl} for component in analysis.components]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "artifact.tar.gz", "digest": {"sha256": artifact_digest}}],
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


def verify_envelope(
    envelope: dict[str, Any], public_key: Ed25519PublicKey, artifact_path: Path
) -> VerificationResult:
    key_id = public_key_id(public_key)
    subject_digest = ""
    signature_valid = False
    artifact_digest_valid = False
    error: str | None = None
    try:
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
        signature_valid = True
        statement = json.loads(payload)
        if statement.get("_type") != STATEMENT_TYPE:
            raise ValueError("unexpected in-toto statement type")
        subjects = statement.get("subject")
        if not isinstance(subjects, list) or len(subjects) != 1:
            raise ValueError("provenance must contain exactly one subject")
        subject_digest = str(subjects[0]["digest"]["sha256"])
        artifact_digest_valid = sha256_file(artifact_path) == subject_digest
        if not artifact_digest_valid:
            error = "artifact digest does not match signed provenance"
    except (InvalidSignature, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        error = f"verification failed: {type(exc).__name__}"
    return VerificationResult(
        signature_valid=signature_valid,
        artifact_digest_valid=artifact_digest_valid,
        key_id=key_id,
        subject_digest=subject_digest,
        error=error,
    )
