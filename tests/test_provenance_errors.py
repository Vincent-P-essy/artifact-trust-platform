from __future__ import annotations

from pathlib import Path

import pytest

from artifact_trust.provenance import (
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_statement,
    verify_envelope,
)


def test_key_generation_permissions_and_refuses_overwrite(tmp_path: Path) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    key_id = generate_keypair(private, public)
    assert key_id.startswith("sha256:")
    assert private.stat().st_mode & 0o777 == 0o600
    assert public.stat().st_mode & 0o777 == 0o644
    with pytest.raises(FileExistsError):
        generate_keypair(private, public)


def test_envelope_rejects_wrong_key_and_malformed_payload(tmp_path: Path) -> None:
    first_private = tmp_path / "first-private.pem"
    first_public = tmp_path / "first-public.pem"
    second_private = tmp_path / "second-private.pem"
    second_public = tmp_path / "second-public.pem"
    generate_keypair(first_private, first_public)
    generate_keypair(second_private, second_public)
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"artifact")
    envelope = sign_statement(
        {"_type": "unexpected", "subject": []}, load_private_key(first_private)
    )
    wrong = verify_envelope(envelope, load_public_key(second_public), artifact)
    assert wrong.signature_valid is False
    malformed = verify_envelope({}, load_public_key(first_public), artifact)
    assert malformed.signature_valid is False
    assert malformed.error is not None
