from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from artifact_trust.cli import app
from artifact_trust.config import Settings


def _environment(settings: Settings) -> dict[str, str]:
    return {
        "ATP_WORK_ROOT": str(settings.work_root),
        "ATP_FIXTURES_ROOT": str(settings.fixtures_root),
        "ATP_PRIVATE_KEY": str(settings.private_key_path),
        "ATP_PUBLIC_KEY": str(settings.public_key_path),
    }


def test_cli_analyze_and_verify(settings: Settings, tmp_path: Path) -> None:
    runner = CliRunner()
    output = tmp_path / "cli-out"
    analyzed = runner.invoke(
        app,
        [
            "analyze",
            "safe-app",
            "--output",
            str(output),
            "--policy-engine",
            "fallback",
        ],
        env=_environment(settings),
    )
    assert analyzed.exit_code == 0, analyzed.output
    assert json.loads(analyzed.stdout)["decision"] == "ALLOW"
    verified = runner.invoke(
        app,
        [
            "verify",
            "--artifact",
            str(output / "artifact.tar.gz"),
            "--provenance",
            str(output / "provenance.dsse.json"),
            "--public-key",
            str(output / "verification-key.pem"),
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.stdout)["artifact_digest_valid"] is True
    assert json.loads(verified.stdout)["evidence_digests_valid"] is True

    envelope = json.loads((output / "provenance.dsse.json").read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    statement["subject"] = [
        subject for subject in statement["subject"] if subject["name"] == "artifact.tar.gz"
    ]
    envelope["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    incomplete_provenance = tmp_path / "incomplete.dsse.json"
    incomplete_provenance.write_text(json.dumps(envelope), encoding="utf-8")
    incomplete = runner.invoke(
        app,
        [
            "verify",
            "--artifact",
            str(output / "artifact.tar.gz"),
            "--provenance",
            str(incomplete_provenance),
            "--public-key",
            str(output / "verification-key.pem"),
        ],
    )
    assert incomplete.exit_code == 1
    assert "complete evidence subject set" in incomplete.output

    with (output / "report.json").open("ab") as handle:
        handle.write(b" ")
    rejected = runner.invoke(
        app,
        [
            "verify",
            "--artifact",
            str(output / "artifact.tar.gz"),
            "--provenance",
            str(output / "provenance.dsse.json"),
            "--public-key",
            str(output / "verification-key.pem"),
        ],
    )
    assert rejected.exit_code == 3
    assert json.loads(rejected.stdout)["evidence_digests_valid"] is False


def test_cli_policy_gate_exits_nonzero(settings: Settings, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "analyze",
            "vulnerable-app",
            "--output",
            str(tmp_path / "quarantine"),
            "--policy-engine",
            "fallback",
        ],
        env=_environment(settings),
    )
    assert result.exit_code == 2
    assert json.loads(result.stdout)["decision"] == "QUARANTINE"


def test_cli_keygen_attack_and_benchmark(settings: Settings, tmp_path: Path) -> None:
    runner = CliRunner()
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generated = runner.invoke(
        app,
        ["keygen", "--private-key", str(private), "--public-key", str(public)],
    )
    assert generated.exit_code == 0
    assert json.loads(generated.stdout)["algorithm"] == "Ed25519"
    repeated = runner.invoke(
        app,
        ["keygen", "--private-key", str(private), "--public-key", str(public)],
    )
    assert repeated.exit_code == 1

    attacked = runner.invoke(
        app,
        ["attack", "safe-app", "--output", str(tmp_path / "attack")],
        env=_environment(settings),
    )
    assert attacked.exit_code == 0, attacked.output
    assert json.loads(attacked.stdout)["blocked"] is True

    measured = runner.invoke(
        app,
        ["benchmark", "safe-app", "--iterations", "1", "--warmups", "0"],
        env=_environment(settings),
    )
    assert measured.exit_code == 0, measured.output
    assert json.loads(measured.stdout)["p95_ms"] > 0


def test_cli_error_external_scan_and_service_commands(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    missing = runner.invoke(
        app,
        ["analyze", "missing", "--output", str(tmp_path / "missing")],
        env=_environment(settings),
    )
    assert missing.exit_code == 1

    monkeypatch.setattr("artifact_trust.adapters.shutil.which", lambda _: None)
    external = runner.invoke(
        app,
        [
            "external-scan",
            "syft",
            str(settings.fixtures_root / "safe-app"),
            "--output",
            str(tmp_path / "external.json"),
        ],
    )
    assert external.exit_code == 1

    served: dict[str, object] = {}
    monkeypatch.setattr(
        "artifact_trust.cli.uvicorn.run",
        lambda *args, **kwargs: served.update({"args": args, "kwargs": kwargs}),
    )
    assert runner.invoke(app, ["serve", "--port", "8999"]).exit_code == 0
    assert served["kwargs"] == {"host": "127.0.0.1", "port": 8999, "reload": False}

    worked: dict[str, object] = {}
    monkeypatch.setattr(
        "artifact_trust.cli.run_worker",
        lambda config, once=False, poll_seconds=1.0: worked.update(
            {"once": once, "poll_seconds": poll_seconds}
        ),
    )
    assert runner.invoke(app, ["worker", "--once"]).exit_code == 0
    assert worked["once"] is True
