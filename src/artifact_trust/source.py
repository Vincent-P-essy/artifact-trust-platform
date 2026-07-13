"""Safe local and pinned HTTPS Git source acquisition."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from contextlib import suppress
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit, urlunsplit

from artifact_trust.config import Settings
from artifact_trust.errors import SourceLimitError, SourceValidationError
from artifact_trust.models import MaterializedSource, SourceSpec
from artifact_trust.util import tree_digest

COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
FIXTURE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_git_source(url: str, commit: str | None, settings: Settings) -> tuple[str, str]:
    if not settings.network_enabled:
        raise SourceValidationError("network source acquisition is disabled")
    if not commit or not COMMIT_RE.fullmatch(commit):
        raise SourceValidationError("Git commit must be an explicit 40-character SHA-1")
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise SourceValidationError("only HTTPS Git URLs are accepted")
    if parsed.username or parsed.password:
        raise SourceValidationError("credentials must not be embedded in source URLs")
    try:
        port = parsed.port
    except ValueError as exc:
        raise SourceValidationError("invalid source URL port") from exc
    if port not in (None, 443):
        raise SourceValidationError("only the default HTTPS port is accepted")
    host = (parsed.hostname or "").rstrip(".").lower()
    if host not in settings.allowed_git_hosts:
        raise SourceValidationError(f"Git host is not allowlisted: {host or '<missing>'}")
    decoded_path = unquote(parsed.path)
    if not decoded_path.startswith("/") or "\\" in decoded_path:
        raise SourceValidationError("invalid repository path")
    parts = [part for part in PurePosixPath(decoded_path).parts if part != "/"]
    if len(parts) < 2 or any(part in {".", "..", ""} for part in parts):
        raise SourceValidationError("repository URL must contain owner and repository")
    if parsed.query or parsed.fragment:
        raise SourceValidationError("query strings and fragments are not accepted")
    canonical = urlunsplit(("https", host, parsed.path.rstrip("/"), "", ""))
    return canonical, commit.lower()


def _within(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or path.is_relative_to(root) for root in roots)


def _copy_snapshot(source: Path, destination: Path, settings: Settings) -> None:
    """Copy an untrusted tree through directory descriptors and no-follow file opens."""
    limits = settings.sandbox
    destination.mkdir(mode=0o700)
    file_count = 0
    directory_count = 0
    total_size = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
        file_flags |= os.O_NOFOLLOW

    def copy_directory(source_fd: int, target: Path) -> None:
        nonlocal file_count, directory_count, total_size
        try:
            entries = sorted(os.scandir(source_fd), key=lambda entry: entry.name)
        except OSError as exc:
            raise SourceValidationError(f"cannot read source directory: {exc}") from exc
        for entry in entries:
            if entry.is_symlink():
                raise SourceValidationError(
                    f"symbolic links are outside the analysis boundary: {entry.name}"
                )
            if entry.is_dir(follow_symlinks=False):
                if entry.name in {".git", ".hg", ".svn", "node_modules", ".venv", "__pycache__"}:
                    continue
                directory_count += 1
                if directory_count > limits.max_files:
                    raise SourceLimitError("source exceeds directory count limit")
                child_target = target / entry.name
                child_target.mkdir(mode=0o700)
                try:
                    child_fd = os.open(entry.name, directory_flags, dir_fd=source_fd)
                except OSError as exc:
                    raise SourceValidationError(
                        f"source directory changed during snapshot: {entry.name}"
                    ) from exc
                try:
                    if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                        raise SourceValidationError(
                            f"source directory changed during snapshot: {entry.name}"
                        )
                    copy_directory(child_fd, child_target)
                finally:
                    os.close(child_fd)
                continue
            try:
                input_fd = os.open(entry.name, file_flags, dir_fd=source_fd)
            except OSError as exc:
                raise SourceValidationError(
                    f"source entry changed during snapshot: {entry.name}"
                ) from exc
            try:
                before = os.fstat(input_fd)
                if not stat.S_ISREG(before.st_mode):
                    raise SourceValidationError(
                        f"non-regular filesystem entry rejected: {entry.name}"
                    )
                file_count += 1
                total_size += before.st_size
                if file_count > limits.max_files:
                    raise SourceLimitError("source exceeds file count limit")
                if before.st_size > limits.max_file_size_bytes:
                    raise SourceLimitError(f"file exceeds size limit: {entry.name}")
                if total_size > limits.max_total_size_bytes:
                    raise SourceLimitError("source exceeds total size limit")
                target_path = target / entry.name
                copied = 0
                with (
                    os.fdopen(os.dup(input_fd), "rb", closefd=True) as input_handle,
                    target_path.open("xb") as output_handle,
                ):
                    while chunk := input_handle.read(1024 * 1024):
                        output_handle.write(chunk)
                        copied += len(chunk)
                after = os.fstat(input_fd)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if copied != before.st_size or any(
                    getattr(before, field) != getattr(after, field) for field in stable_fields
                ):
                    raise SourceValidationError(
                        f"source file changed during snapshot: {entry.name}"
                    )
                target_path.chmod(0o400)
            finally:
                os.close(input_fd)

    try:
        root_fd = os.open(source, directory_flags)
    except OSError as exc:
        raise SourceValidationError(f"cannot open source root: {exc}") from exc
    try:
        copy_directory(root_fd, destination)
    finally:
        os.close(root_fd)


def _snapshot_local_tree(source: Path, settings: Settings) -> Path:
    if settings.work_root == source or settings.work_root.is_relative_to(source):
        raise SourceValidationError("work root must be outside the source tree")
    settings.ensure_directories()
    parent = Path(tempfile.mkdtemp(prefix="snapshot-", dir=settings.work_root / "sources"))
    destination = parent / "source"
    try:
        _copy_snapshot(source, destination, settings)
        for directory in sorted(
            (path for path in destination.rglob("*") if path.is_dir()), reverse=True
        ):
            directory.chmod(0o500)
        destination.chmod(0o500)
        return destination
    except Exception:
        shutil.rmtree(parent, ignore_errors=True)
        raise


def remove_materialized_source(source: MaterializedSource, settings: Settings) -> None:
    """Remove a private materialization after restoring owner permissions."""
    _remove_materialized_root(source.root, settings.work_root / "sources")


def _remove_materialized_root(root: Path, sources_root: Path) -> None:
    """Remove only a materialization created below the private sources directory."""
    parent = root.parent
    if (
        root.name != "source"
        or not parent.name.startswith(("snapshot-", "git-"))
        or parent.parent.resolve() != sources_root.resolve()
    ):
        return
    for path in [root, *root.rglob("*")]:
        with suppress(OSError):
            path.chmod(0o700 if path.is_dir() else 0o600)
    shutil.rmtree(parent, ignore_errors=True)


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
    }
    return environment


def _run_git(arguments: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[bytes]:
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "filter.lfs.smudge=",
        "-c",
        "filter.lfs.required=false",
        "-c",
        "http.followRedirects=false",
        *arguments,
    ]
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        message = detail.decode("utf-8", errors="replace")[-500:].strip()
        raise SourceValidationError(
            f"Git source acquisition failed: {message or type(exc).__name__}"
        ) from exc


def _safe_extract(archive: Path, destination: Path, settings: Settings) -> None:
    count = 0
    total = 0
    with tarfile.open(archive, "r:") as bundle:
        for member in sorted(bundle.getmembers(), key=lambda item: item.name):
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts or "\\" in member.name:
                raise SourceValidationError("unsafe path in Git archive")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            if not member.isfile():
                raise SourceValidationError(
                    "links and special files are rejected from Git archives"
                )
            count += 1
            total += member.size
            if count > settings.sandbox.max_files:
                raise SourceLimitError("Git archive exceeds file count limit")
            if member.size > settings.sandbox.max_file_size_bytes:
                raise SourceLimitError(f"Git archive file exceeds size limit: {member.name}")
            if total > settings.sandbox.max_total_size_bytes:
                raise SourceLimitError("Git archive exceeds total size limit")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = bundle.extractfile(member)
            if source is None:
                raise SourceValidationError("cannot read regular file from Git archive")
            with target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target.chmod(0o600)


def _materialize_git(spec: SourceSpec, settings: Settings) -> tuple[Path, str, str]:
    url, commit = validate_git_source(spec.location, spec.commit, settings)
    settings.ensure_directories()
    checkout = Path(tempfile.mkdtemp(prefix="git-", dir=settings.work_root / "sources"))
    repository = checkout / "repository"
    source = checkout / "source"
    try:
        repository.mkdir(mode=0o700)
        source.mkdir(mode=0o700)
        timeout = max(settings.sandbox.cpu_seconds * 2, 10)
        _run_git(["init", "--quiet"], repository, timeout)
        _run_git(["remote", "add", "origin", url], repository, timeout)
        _run_git(["fetch", "--quiet", "--depth=1", "origin", commit], repository, timeout)
        resolved = (
            _run_git(["rev-parse", "FETCH_HEAD^{commit}"], repository, timeout)
            .stdout.decode()
            .strip()
        )
        if resolved.lower() != commit:
            raise SourceValidationError("fetched commit does not match requested commit")
        archive = checkout / "source.tar"
        _run_git(["archive", "--format=tar", f"--output={archive}", commit], repository, timeout)
        _safe_extract(archive, source, settings)
        shutil.rmtree(repository)
        archive.unlink(missing_ok=True)
        return source, url, commit
    except Exception:
        shutil.rmtree(checkout, ignore_errors=True)
        raise


def materialize_source(spec: SourceSpec, settings: Settings) -> MaterializedSource:
    if spec.kind == "fixture":
        if not FIXTURE_RE.fullmatch(spec.location):
            raise SourceValidationError("invalid fixture name")
        original = (settings.fixtures_root / spec.location).resolve(strict=True)
        if not original.is_relative_to(settings.fixtures_root):
            raise SourceValidationError("fixture escapes fixture root")
        root = _snapshot_local_tree(original, settings)
        canonical = f"fixture:{spec.location}"
        commit = None
        pinned = True
    elif spec.kind == "local":
        original = Path(spec.location).expanduser().resolve(strict=True)
        if not _within(original, settings.allowed_local_roots):
            raise SourceValidationError("local source is outside configured roots")
        root = _snapshot_local_tree(original, settings)
        canonical = f"local:{original.name}"
        commit = None
        pinned = False
    else:
        root, canonical, commit = _materialize_git(spec, settings)
        pinned = True
    try:
        digest, file_count, total_size = tree_digest(root, settings.sandbox)
        if spec.kind == "git":
            for directory in sorted(
                (path for path in root.rglob("*") if path.is_dir()), reverse=True
            ):
                directory.chmod(0o500)
            for path in root.rglob("*"):
                if path.is_file():
                    path.chmod(0o400)
            root.chmod(0o500)
    except Exception:
        _remove_materialized_root(root, settings.work_root / "sources")
        raise
    return MaterializedSource(
        root=root,
        kind=spec.kind,
        canonical_location=canonical,
        commit=commit,
        digest_sha256=digest,
        file_count=file_count,
        total_size_bytes=total_size,
        pinned=pinned,
    )
