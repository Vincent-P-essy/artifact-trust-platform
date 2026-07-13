"""Safe local and pinned HTTPS Git source acquisition."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tarfile
import tempfile
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
    repository.mkdir(mode=0o700)
    source.mkdir(mode=0o700)
    timeout = max(settings.sandbox.cpu_seconds * 2, 10)
    _run_git(["init", "--quiet"], repository, timeout)
    _run_git(["remote", "add", "origin", url], repository, timeout)
    _run_git(["fetch", "--quiet", "--depth=1", "origin", commit], repository, timeout)
    resolved = (
        _run_git(["rev-parse", "FETCH_HEAD^{commit}"], repository, timeout).stdout.decode().strip()
    )
    if resolved.lower() != commit:
        raise SourceValidationError("fetched commit does not match requested commit")
    archive = checkout / "source.tar"
    _run_git(["archive", "--format=tar", f"--output={archive}", commit], repository, timeout)
    _safe_extract(archive, source, settings)
    shutil.rmtree(repository)
    archive.unlink(missing_ok=True)
    return source, url, commit


def materialize_source(spec: SourceSpec, settings: Settings) -> MaterializedSource:
    if spec.kind == "fixture":
        if not FIXTURE_RE.fullmatch(spec.location):
            raise SourceValidationError("invalid fixture name")
        root = (settings.fixtures_root / spec.location).resolve(strict=True)
        if not root.is_relative_to(settings.fixtures_root):
            raise SourceValidationError("fixture escapes fixture root")
        canonical = f"fixture:{spec.location}"
        commit = None
        pinned = True
    elif spec.kind == "local":
        root = Path(spec.location).expanduser().resolve(strict=True)
        if not _within(root, settings.allowed_local_roots):
            raise SourceValidationError("local source is outside configured roots")
        canonical = f"local:{root.name}"
        commit = None
        pinned = False
    else:
        root, canonical, commit = _materialize_git(spec, settings)
        pinned = True
    digest, file_count, total_size = tree_digest(root, settings.sandbox)
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
