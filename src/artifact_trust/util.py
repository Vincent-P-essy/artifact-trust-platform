"""Small deterministic serialization and hashing helpers."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from artifact_trust.errors import SourceLimitError, SourceValidationError
from artifact_trust.models import SandboxPolicy

IGNORED_DIRECTORIES = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "__pycache__"})


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize without platform- or locale-dependent whitespace."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
    path.write_text(payload + "\n", encoding="utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_safe_files(root: Path, limits: SandboxPolicy) -> Iterator[tuple[str, Path, int]]:
    """Yield regular files only, sorted by portable relative path.

    Symbolic links are rejected instead of followed. VCS metadata, dependency caches,
    and bytecode directories are excluded from the evidence boundary.
    """
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise SourceValidationError(f"source is not a directory: {root}")

    files: list[tuple[str, Path, int]] = []
    stack = [root]
    total_size = 0
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise SourceValidationError(f"cannot read source directory: {exc}") from exc
        for entry in entries:
            entry_path = Path(entry.path)
            if entry.is_symlink():
                raise SourceValidationError(
                    f"symbolic links are outside the analysis boundary: {entry_path.relative_to(root)}"
                )
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in IGNORED_DIRECTORIES:
                    stack.append(entry_path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise SourceValidationError(
                    f"non-regular filesystem entry rejected: {entry_path.relative_to(root)}"
                )
            stat = entry.stat(follow_symlinks=False)
            if stat.st_size > limits.max_file_size_bytes:
                raise SourceLimitError(f"file exceeds size limit: {entry_path.relative_to(root)}")
            total_size += stat.st_size
            if total_size > limits.max_total_size_bytes:
                raise SourceLimitError("source exceeds total size limit")
            relative = entry_path.relative_to(root).as_posix()
            files.append((relative, entry_path, stat.st_size))
            if len(files) > limits.max_files:
                raise SourceLimitError("source exceeds file count limit")

    yield from sorted(files, key=lambda item: item[0])


def tree_digest(root: Path, limits: SandboxPolicy) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    count = 0
    total = 0
    for relative, path, size in iter_safe_files(root, limits):
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        count += 1
        total += size
    return digest.hexdigest(), count, total
