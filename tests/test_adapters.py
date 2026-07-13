from __future__ import annotations

from pathlib import Path

import pytest

from artifact_trust.adapters import Adapter, adapter_command, run_adapter
from artifact_trust.errors import ArtifactTrustError


def test_adapter_commands_do_not_use_a_shell(tmp_path: Path) -> None:
    target = tmp_path / "source"
    target.mkdir()
    output = tmp_path / "result.json"
    assert adapter_command(Adapter.SYFT, target, output)[0] == "syft"
    assert "dir:" in adapter_command(Adapter.SYFT, target, output)[1]
    assert adapter_command(Adapter.GRYPE, target, output)[1].startswith("sbom:")
    assert "--no-git" in adapter_command(Adapter.GITLEAKS, target, output)


def test_missing_adapter_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "source"
    target.mkdir()
    monkeypatch.setattr("artifact_trust.adapters.shutil.which", lambda _: None)
    with pytest.raises(ArtifactTrustError, match="not installed"):
        run_adapter(Adapter.SYFT, target, tmp_path / "result.json")
