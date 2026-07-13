"""Deterministic source artifact creation without executing repository code."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

from artifact_trust.models import SandboxPolicy
from artifact_trust.util import iter_safe_files, sha256_file


def build_source_artifact(
    source: Path, destination: Path, limits: SandboxPolicy
) -> tuple[str, int]:
    """Create a byte-for-byte reproducible gzip-compressed tarball."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        destination.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as zipped,
        tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as bundle,
    ):
        for relative, path, size in iter_safe_files(source, limits):
            info = tarfile.TarInfo(relative)
            info.size = size
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.pax_headers = {}
            with path.open("rb") as handle:
                data = io.BytesIO(handle.read())
            bundle.addfile(info, data)
    return sha256_file(destination), destination.stat().st_size
