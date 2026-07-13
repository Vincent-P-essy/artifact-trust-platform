from __future__ import annotations

import io
import tarfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifact_trust.config import Settings
from artifact_trust.errors import SourceValidationError
from artifact_trust.models import SourceSpec
from artifact_trust.source import (
    _git_environment,
    _materialize_git,
    _run_git,
    _safe_extract,
    validate_git_source,
)


def _tar(path: Path, name: str = "manifest.txt", kind: str = "file") -> None:
    with tarfile.open(path, "w") as bundle:
        info = tarfile.TarInfo(name)
        if kind == "file":
            payload = b"content"
            info.size = len(payload)
            bundle.addfile(info, io.BytesIO(payload))
        elif kind == "directory":
            info.type = tarfile.DIRTYPE
            bundle.addfile(info)
        else:
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            bundle.addfile(info)


def test_safe_extract_regular_file_and_directory(settings: Settings, tmp_path: Path) -> None:
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as bundle:
        directory = tarfile.TarInfo("sub")
        directory.type = tarfile.DIRTYPE
        bundle.addfile(directory)
        payload = b"content"
        regular = tarfile.TarInfo("sub/file.txt")
        regular.size = len(payload)
        bundle.addfile(regular, io.BytesIO(payload))
    destination = tmp_path / "out"
    destination.mkdir()
    _safe_extract(archive, destination, settings)
    assert (destination / "sub" / "file.txt").read_bytes() == b"content"


@pytest.mark.parametrize(("name", "kind"), [("../escape", "file"), ("link", "link")])
def test_safe_extract_rejects_unsafe_members(
    settings: Settings, tmp_path: Path, name: str, kind: str
) -> None:
    archive = tmp_path / "unsafe.tar"
    _tar(archive, name, kind)
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(SourceValidationError):
        _safe_extract(archive, destination, settings)


def test_materialize_git_with_fixed_git_boundary(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "a" * 40
    enabled = replace(settings, network_enabled=True, work_root=tmp_path / "work")

    def fake_git(arguments: list[str], cwd: Path, timeout: int) -> SimpleNamespace:
        del timeout
        if arguments[0] == "rev-parse":
            return SimpleNamespace(stdout=(commit + "\n").encode())
        if arguments[0] == "archive":
            output = next(item for item in arguments if item.startswith("--output="))
            _tar(Path(output.split("=", 1)[1]))
        return SimpleNamespace(stdout=b"")

    monkeypatch.setattr("artifact_trust.source._run_git", fake_git)
    root, url, resolved = _materialize_git(
        SourceSpec(kind="git", location="https://github.com/o/r.git", commit=commit), enabled
    )
    assert url == "https://github.com/o/r.git"
    assert resolved == commit
    assert (root / "manifest.txt").read_text(encoding="utf-8") == "content"


def test_git_helpers_and_validation_edges(settings: Settings, tmp_path: Path) -> None:
    environment = _git_environment()
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert _run_git(["--version"], tmp_path, 5).stdout.startswith(b"git version")
    with pytest.raises(SourceValidationError, match="failed"):
        _run_git(["not-a-real-command"], tmp_path, 5)
    enabled = replace(settings, network_enabled=True)
    with pytest.raises(SourceValidationError, match="port"):
        validate_git_source("https://github.com:444/o/r", "a" * 40, enabled)
    with pytest.raises(SourceValidationError, match="owner"):
        validate_git_source("https://github.com/only-one", "a" * 40, enabled)
