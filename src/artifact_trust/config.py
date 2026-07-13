"""Environment-backed configuration with secure defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from artifact_trust.models import SandboxPolicy

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parents[1]
DEFAULT_FIXTURES_ROOT = PROJECT_ROOT / "fixtures"


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip().lower() for item in value.split(",") if item.strip())


def _paths(value: str) -> tuple[Path, ...]:
    return tuple(Path(item).expanduser().resolve() for item in value.split(os.pathsep) if item)


@dataclass(frozen=True, slots=True)
class Settings:
    work_root: Path
    fixtures_root: Path
    allowed_local_roots: tuple[Path, ...]
    allowed_git_hosts: tuple[str, ...]
    network_enabled: bool
    sandbox: SandboxPolicy
    private_key_path: Path | None
    public_key_path: Path | None
    source_date_epoch: int

    @classmethod
    def from_env(cls) -> Settings:
        fixtures_root = (
            Path(os.getenv("ATP_FIXTURES_ROOT", str(DEFAULT_FIXTURES_ROOT))).expanduser().resolve()
        )
        local_roots = _paths(os.getenv("ATP_ALLOWED_LOCAL_ROOTS", str(fixtures_root)))
        network = os.getenv("ATP_ALLOW_NETWORK", "0") == "1"
        command_execution = "git-fetch-only" if network else "disabled"
        private = os.getenv("ATP_PRIVATE_KEY")
        public = os.getenv("ATP_PUBLIC_KEY")
        return cls(
            work_root=Path(os.getenv("ATP_WORK_ROOT", "/tmp/artifact-trust")).resolve(),
            fixtures_root=fixtures_root,
            allowed_local_roots=local_roots,
            allowed_git_hosts=_csv(os.getenv("ATP_ALLOWED_GIT_HOSTS", "github.com")),
            network_enabled=network,
            sandbox=SandboxPolicy(
                network_enabled=network,
                command_execution=command_execution,
                cpu_seconds=int(os.getenv("ATP_CPU_SECONDS", "30")),
                memory_mb=int(os.getenv("ATP_MEMORY_MB", "512")),
                max_files=int(os.getenv("ATP_MAX_FILES", "10000")),
                max_file_size_bytes=int(os.getenv("ATP_MAX_FILE_SIZE", "5000000")),
                max_total_size_bytes=int(os.getenv("ATP_MAX_TOTAL_SIZE", "100000000")),
                pids=int(os.getenv("ATP_MAX_PIDS", "64")),
            ),
            private_key_path=Path(private).resolve() if private else None,
            public_key_path=Path(public).resolve() if public else None,
            source_date_epoch=int(os.getenv("SOURCE_DATE_EPOCH", "0")),
        )

    def ensure_directories(self) -> None:
        self.work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ("pending", "running", "completed", "failed", "results", "sources"):
            (self.work_root / name).mkdir(exist_ok=True, mode=0o700)
