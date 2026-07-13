"""Command-line interface and policy-gate exit codes."""

from __future__ import annotations

import json
from dataclasses import replace
from enum import StrEnum
from pathlib import Path

import typer
import uvicorn

from artifact_trust.adapters import Adapter, run_adapter
from artifact_trust.attack import run_tamper_scenario
from artifact_trust.benchmark import benchmark_pipeline
from artifact_trust.config import Settings
from artifact_trust.errors import ArtifactTrustError
from artifact_trust.models import Decision, SourceSpec
from artifact_trust.pipeline import run_pipeline
from artifact_trust.provenance import (
    EVIDENCE_SUBJECTS,
    envelope_subject_digests,
    generate_keypair,
    load_public_key,
    verify_evidence_directory,
)
from artifact_trust.util import write_json
from artifact_trust.worker import run_worker

app = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
    help="Generate and enforce deterministic software supply-chain evidence.",
)


class SourceKind(StrEnum):
    FIXTURE = "fixture"
    LOCAL = "local"
    GIT = "git"


class PolicyEngine(StrEnum):
    AUTO = "auto"
    FALLBACK = "fallback"
    OPA = "opa"


def _settings(
    source: str,
    kind: SourceKind,
    private_key: Path | None,
    public_key: Path | None,
    allow_network: bool,
    allowed_host: list[str],
) -> Settings:
    settings = Settings.from_env()
    roots = settings.allowed_local_roots
    if kind == SourceKind.LOCAL:
        roots = (*roots, Path(source).expanduser().resolve())
    network = settings.network_enabled or allow_network
    sandbox = settings.sandbox.model_copy(
        update={
            "network_enabled": network,
            "command_execution": "git-fetch-only" if network else "disabled",
        }
    )
    return replace(
        settings,
        allowed_local_roots=roots,
        allowed_git_hosts=tuple(item.lower() for item in allowed_host)
        or settings.allowed_git_hosts,
        network_enabled=network,
        sandbox=sandbox,
        private_key_path=private_key.resolve() if private_key else settings.private_key_path,
        public_key_path=public_key.resolve() if public_key else settings.public_key_path,
    )


def _spec(source: str, kind: SourceKind, commit: str | None) -> SourceSpec:
    return SourceSpec(kind=kind.value, location=source, commit=commit)


@app.command()
def keygen(
    private_key: Path = typer.Option(Path("signing-key.pem"), help="Private key destination."),
    public_key: Path = typer.Option(Path("verification-key.pem"), help="Public key destination."),
) -> None:
    """Generate an Ed25519 signing and verification keypair."""
    try:
        key_id = generate_keypair(private_key.resolve(), public_key.resolve())
    except (FileExistsError, OSError, ValueError, TypeError) as exc:
        typer.echo(f"key generation failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps({"algorithm": "Ed25519", "key_id": key_id}, sort_keys=True))


@app.command()
def analyze(
    source: str = typer.Argument(..., help="Fixture name, local directory, or HTTPS Git URL."),
    output: Path = typer.Option(Path("out"), help="New or empty output directory."),
    kind: SourceKind = typer.Option(SourceKind.FIXTURE, case_sensitive=False),
    commit: str | None = typer.Option(None, help="Required full commit SHA for Git sources."),
    private_key: Path | None = typer.Option(None, help="Ed25519 private key PEM."),
    public_key: Path | None = typer.Option(None, help="Matching Ed25519 public key PEM."),
    policy_engine: PolicyEngine = typer.Option(PolicyEngine.AUTO, case_sensitive=False),
    allow_network: bool = typer.Option(False, help="Permit validated Git fetches."),
    allowed_host: list[str] | None = typer.Option(None, help="Exact Git host allowlist entry."),
    enforce: bool = typer.Option(True, help="Exit non-zero for quarantine or rejection."),
) -> None:
    """Analyze, sign, verify, and decide whether an artifact may be published."""
    try:
        settings = _settings(
            source,
            kind,
            private_key,
            public_key,
            allow_network,
            allowed_host or [],
        )
        report = run_pipeline(
            _spec(source, kind, commit), output.resolve(), settings, policy_engine.value
        )
    except (
        ArtifactTrustError,
        FileExistsError,
        FileNotFoundError,
        OSError,
        ValueError,
        TypeError,
    ) as exc:
        typer.echo(f"analysis failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(
        json.dumps(
            {
                "report_id": report.report_id,
                "decision": report.policy.decision.value,
                "output": str(output.resolve()),
            },
            sort_keys=True,
        )
    )
    if enforce and report.policy.decision != Decision.ALLOW:
        raise typer.Exit(2 if report.policy.decision == Decision.QUARANTINE else 3)


@app.command()
def verify(
    artifact: Path = typer.Option(..., exists=True, dir_okay=False),
    provenance: Path = typer.Option(..., exists=True, dir_okay=False),
    public_key: Path = typer.Option(..., exists=True, dir_okay=False),
) -> None:
    """Verify the DSSE signature and every file in a complete evidence bundle."""
    try:
        envelope = json.loads(provenance.read_text(encoding="utf-8"))
        subjects = envelope_subject_digests(envelope)
        if tuple(sorted(subjects)) != tuple(sorted(EVIDENCE_SUBJECTS)):
            raise ValueError("provenance does not bind the complete evidence subject set")
        evidence_root = provenance.resolve().parent
        if artifact.resolve() != evidence_root / "artifact.tar.gz":
            raise ValueError("artifact path does not match the signed evidence directory")
        result = verify_evidence_directory(envelope, load_public_key(public_key), evidence_root)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        typer.echo(f"verification failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(result.model_dump(mode="json"), sort_keys=True))
    if not (
        result.signature_valid
        and result.provenance_valid
        and result.artifact_digest_valid
        and result.evidence_digests_valid
    ):
        raise typer.Exit(3)


@app.command()
def attack(
    source: str = typer.Argument("safe-app"),
    output: Path = typer.Option(Path("attack-out")),
    kind: SourceKind = typer.Option(SourceKind.FIXTURE, case_sensitive=False),
    commit: str | None = typer.Option(None),
    private_key: Path | None = typer.Option(None),
    public_key: Path | None = typer.Option(None),
) -> None:
    """Alter a built artifact and prove that publication is rejected."""
    try:
        settings = _settings(source, kind, private_key, public_key, False, [])
        result = run_tamper_scenario(_spec(source, kind, commit), output.resolve(), settings)
    except (ArtifactTrustError, OSError, ValueError, TypeError) as exc:
        typer.echo(f"attack scenario failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(result, sort_keys=True))
    if not result["blocked"]:
        raise typer.Exit(4)


@app.command("benchmark")
def benchmark_command(
    source: str = typer.Argument("safe-app"),
    kind: SourceKind = typer.Option(SourceKind.FIXTURE, case_sensitive=False),
    iterations: int = typer.Option(10, min=1, max=100),
    warmups: int = typer.Option(1, min=0, max=20),
    output: Path | None = typer.Option(None, help="Optional metrics JSON path."),
) -> None:
    """Measure complete pipeline latency and report p50 and p95."""
    try:
        settings = _settings(source, kind, None, None, False, [])
        result = benchmark_pipeline(_spec(source, kind, None), settings, iterations, warmups)
        if output:
            write_json(output.resolve(), result)
    except (ArtifactTrustError, OSError, ValueError, TypeError) as exc:
        typer.echo(f"benchmark failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(result, sort_keys=True))


@app.command()
def external_scan(
    adapter: Adapter = typer.Argument(...),
    target: Path = typer.Argument(..., exists=True),
    output: Path = typer.Option(...),
    timeout: int = typer.Option(120, min=1, max=600),
) -> None:
    """Run a separately installed, explicitly requested scanner adapter."""
    try:
        result = run_adapter(adapter, target, output, timeout)
    except (ArtifactTrustError, OSError, ValueError) as exc:
        typer.echo(f"external scan failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps({"adapter": adapter.value, "output": str(result)}, sort_keys=True))


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1"),
    port: int = typer.Option(8000, min=1, max=65535),
) -> None:
    """Serve the API and dashboard; this process never runs analyses."""
    uvicorn.run("artifact_trust.api:app", host=host, port=port, reload=False)


@app.command()
def worker(
    once: bool = typer.Option(False, help="Process at most one job and exit."),
    poll_seconds: float = typer.Option(1.0, min=0.1, max=30.0),
) -> None:
    """Run the separate, resource-limited analysis worker."""
    run_worker(Settings.from_env(), once=once, poll_seconds=poll_seconds)


def worker_entrypoint() -> None:
    run_worker(Settings.from_env())


if __name__ == "__main__":
    app()
