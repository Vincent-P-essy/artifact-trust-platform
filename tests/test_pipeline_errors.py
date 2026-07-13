from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from artifact_trust.config import Settings
from artifact_trust.models import SourceSpec
from artifact_trust.pipeline import ensure_signing_key, run_pipeline
from artifact_trust.provenance import generate_keypair


def test_pipeline_rejects_nonempty_output(settings: Settings, tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    (output / "existing").write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError, match="not empty"):
        run_pipeline(SourceSpec(kind="fixture", location="safe-app"), output, settings, "fallback")
    assert (output / "existing").read_text(encoding="utf-8") == "keep"


def test_pipeline_derives_public_key_when_only_private_configured(
    settings: Settings, tmp_path: Path
) -> None:
    derived = replace(settings, work_root=tmp_path / "work", public_key_path=None)
    private, public = ensure_signing_key(derived)
    assert private == settings.private_key_path
    assert public.is_file()
    report = run_pipeline(
        SourceSpec(kind="fixture", location="safe-app"), tmp_path / "out", derived, "fallback"
    )
    assert report.verification.signature_valid


def test_pipeline_auto_generates_development_key(settings: Settings, tmp_path: Path) -> None:
    ephemeral = replace(
        settings, work_root=tmp_path / "work", private_key_path=None, public_key_path=None
    )
    private, public = ensure_signing_key(ephemeral)
    assert private.is_file() and public.is_file()
    assert ensure_signing_key(ephemeral) == (private, public)


def test_pipeline_rejects_mismatched_keys(settings: Settings, tmp_path: Path) -> None:
    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"
    generate_keypair(other_private, other_public)
    mismatched = replace(settings, public_key_path=other_public)
    with pytest.raises(ValueError, match="do not match"):
        run_pipeline(
            SourceSpec(kind="fixture", location="safe-app"),
            tmp_path / "mismatch",
            mismatched,
            "fallback",
        )
