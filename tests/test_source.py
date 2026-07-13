from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from artifact_trust.config import Settings
from artifact_trust.errors import SourceLimitError, SourceValidationError
from artifact_trust.models import SandboxPolicy, SourceSpec
from artifact_trust.source import materialize_source, validate_git_source
from artifact_trust.util import tree_digest


def test_materialize_named_fixture(settings: Settings) -> None:
    source = materialize_source(SourceSpec(kind="fixture", location="safe-app"), settings)
    assert source.pinned is True
    assert source.canonical_location == "fixture:safe-app"
    assert source.file_count == 3
    assert len(source.digest_sha256) == 64


@pytest.mark.parametrize(
    ("url", "commit", "message"),
    [
        ("http://github.com/o/r", "a" * 40, "HTTPS"),
        ("https://example.com/o/r", "a" * 40, "allowlisted"),
        ("https://user@github.com/o/r", "a" * 40, "credentials"),
        ("https://github.com/o/r?ref=main", "a" * 40, "query"),
        ("https://github.com/o/r", "short", "40-character"),
    ],
)
def test_git_source_validation_rejects_unsafe_inputs(
    settings: Settings, url: str, commit: str, message: str
) -> None:
    enabled = replace(settings, network_enabled=True)
    with pytest.raises(SourceValidationError, match=message):
        validate_git_source(url, commit, enabled)


def test_git_source_requires_explicit_network_enable(settings: Settings) -> None:
    with pytest.raises(SourceValidationError, match="disabled"):
        validate_git_source("https://github.com/o/r.git", "a" * 40, settings)


def test_git_source_returns_canonical_pinned_input(settings: Settings) -> None:
    enabled = replace(settings, network_enabled=True)
    assert validate_git_source("https://github.com/O/R.git/", "A" * 40, enabled) == (
        "https://github.com/O/R.git",
        "a" * 40,
    )


def test_local_source_outside_allowlist_is_rejected(settings: Settings, tmp_path: Path) -> None:
    source = tmp_path / "outside"
    source.mkdir()
    with pytest.raises(SourceValidationError, match="outside"):
        materialize_source(SourceSpec(kind="local", location=str(source)), settings)


def test_symbolic_link_is_rejected(settings: Settings, tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "data.txt").write_text("safe", encoding="utf-8")
    (root / "link").symlink_to(root / "data.txt")
    with pytest.raises(SourceValidationError, match="symbolic"):
        tree_digest(root, settings.sandbox)


def test_file_limit_is_enforced(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "large").write_bytes(b"x" * 2048)
    limits = SandboxPolicy(max_file_size_bytes=1024, max_total_size_bytes=4096)
    with pytest.raises(SourceLimitError, match="size limit"):
        tree_digest(root, limits)
