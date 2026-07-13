from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from artifact_trust.config import Settings
from artifact_trust.errors import SourceLimitError, SourceValidationError
from artifact_trust.models import MaterializedSource, SandboxPolicy, SourceSpec
from artifact_trust.source import (
    _copy_snapshot,
    materialize_source,
    remove_materialized_source,
    validate_git_source,
)
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


def test_local_source_is_copied_to_one_private_snapshot(settings: Settings, tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.mkdir()
    (original / "data.txt").write_text("first", encoding="utf-8")
    isolated = replace(
        settings,
        work_root=tmp_path / "work",
        allowed_local_roots=(original,),
    )
    source = materialize_source(SourceSpec(kind="local", location=str(original)), isolated)
    try:
        assert source.root != original
        assert source.root.is_relative_to(isolated.work_root / "sources")
        (original / "data.txt").write_text("changed", encoding="utf-8")
        assert (source.root / "data.txt").read_text(encoding="utf-8") == "first"
        assert source.root.stat().st_mode & 0o222 == 0
    finally:
        remove_materialized_source(source, isolated)


def test_snapshot_recurses_but_excludes_dependency_and_vcs_trees(
    settings: Settings, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "nested" / "data.txt").write_text("safe", encoding="utf-8")
    for ignored in (".git", "node_modules", "__pycache__"):
        (source / ignored).mkdir()
        (source / ignored / "excluded").write_text("ignored", encoding="utf-8")
    destination = tmp_path / "snapshot"
    _copy_snapshot(source, destination, settings)
    assert (destination / "nested" / "data.txt").read_text(encoding="utf-8") == "safe"
    assert not (destination / ".git").exists()
    assert not (destination / "node_modules").exists()
    assert not (destination / "__pycache__").exists()


@pytest.mark.parametrize(
    ("files", "directories", "sandbox", "message"),
    [
        ({"one": b"1", "two": b"2"}, (), SandboxPolicy(max_files=1), "file count"),
        ({}, ("one", "two"), SandboxPolicy(max_files=1), "directory count"),
        (
            {"large": b"x" * 2048},
            (),
            SandboxPolicy(max_file_size_bytes=1024, max_total_size_bytes=4096),
            "file exceeds size",
        ),
        (
            {"one": b"x" * 700, "two": b"x" * 700},
            (),
            SandboxPolicy(max_file_size_bytes=1024, max_total_size_bytes=1024),
            "total size",
        ),
    ],
)
def test_snapshot_enforces_limits_before_analysis(
    settings: Settings,
    tmp_path: Path,
    files: dict[str, bytes],
    directories: tuple[str, ...],
    sandbox: SandboxPolicy,
    message: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for name, payload in files.items():
        (source / name).write_bytes(payload)
    for name in directories:
        (source / name).mkdir()
    destination = tmp_path / "snapshot"
    limited = replace(settings, sandbox=sandbox)
    with pytest.raises(SourceLimitError, match=message):
        _copy_snapshot(source, destination, limited)


def test_snapshot_rejects_symlink_fifo_and_non_directory_root(
    settings: Settings, tmp_path: Path
) -> None:
    symlink_source = tmp_path / "symlink-source"
    symlink_source.mkdir()
    (symlink_source / "target").write_text("data", encoding="utf-8")
    (symlink_source / "link").symlink_to("target")
    with pytest.raises(SourceValidationError, match="symbolic"):
        _copy_snapshot(symlink_source, tmp_path / "symlink-snapshot", settings)

    fifo_source = tmp_path / "fifo-source"
    fifo_source.mkdir()
    os.mkfifo(fifo_source / "pipe")
    with pytest.raises(SourceValidationError, match="non-regular"):
        _copy_snapshot(fifo_source, tmp_path / "fifo-snapshot", settings)

    regular_file = tmp_path / "not-a-directory"
    regular_file.write_text("data", encoding="utf-8")
    with pytest.raises(SourceValidationError, match="cannot open source root"):
        _copy_snapshot(regular_file, tmp_path / "file-snapshot", settings)


def test_work_root_must_not_be_nested_inside_local_source(
    settings: Settings, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    nested = replace(
        settings,
        work_root=source / "work",
        allowed_local_roots=(source,),
    )
    with pytest.raises(SourceValidationError, match="work root"):
        materialize_source(SourceSpec(kind="local", location=str(source)), nested)


def test_cleanup_refuses_similarly_named_directory_outside_private_source_root(
    settings: Settings, tmp_path: Path
) -> None:
    root = tmp_path / "snapshot-forged" / "source"
    root.mkdir(parents=True)
    (root / "keep.txt").write_text("keep", encoding="utf-8")
    forged = MaterializedSource(
        root=root,
        kind="local",
        canonical_location="local:forged",
        commit=None,
        digest_sha256="0" * 64,
        file_count=1,
        total_size_bytes=4,
        pinned=False,
    )
    remove_materialized_source(forged, settings)
    assert (root / "keep.txt").is_file()
