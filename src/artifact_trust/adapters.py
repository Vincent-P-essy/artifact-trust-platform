"""Opt-in adapters for established scanners.

They are intentionally excluded from the deterministic default pipeline. Binaries must
be installed and version-pinned by the operator. Repository code is never executed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from enum import StrEnum
from pathlib import Path

from artifact_trust.errors import ArtifactTrustError


class Adapter(StrEnum):
    SYFT = "syft"
    GRYPE = "grype"
    GITLEAKS = "gitleaks"


def adapter_command(adapter: Adapter, target: Path, output: Path) -> list[str]:
    if adapter == Adapter.SYFT:
        return ["syft", f"dir:{target}", "--output", f"cyclonedx-json={output}"]
    if adapter == Adapter.GRYPE:
        return ["grype", f"sbom:{target}", "--output", "json", "--file", str(output)]
    return [
        "gitleaks",
        "detect",
        "--no-git",
        "--source",
        str(target),
        "--report-format",
        "json",
        "--report-path",
        str(output),
    ]


def run_adapter(adapter: Adapter, target: Path, output: Path, timeout: int = 120) -> Path:
    target = target.resolve(strict=True)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    executable = shutil.which(adapter.value)
    if executable is None:
        raise ArtifactTrustError(f"optional adapter is not installed: {adapter.value}")
    command = adapter_command(adapter, target, output)
    command[0] = executable
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
    }
    try:
        result = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=max(1, min(timeout, 600)),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ArtifactTrustError(f"optional adapter timed out: {adapter.value}") from exc
    if result.returncode != 0:
        detail = (
            result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "non-zero exit"
        )
        raise ArtifactTrustError(f"optional adapter failed: {adapter.value}: {detail[:200]}")
    if not output.is_file():
        raise ArtifactTrustError(f"optional adapter produced no output: {adapter.value}")
    return output
