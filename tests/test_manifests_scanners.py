from __future__ import annotations

from artifact_trust.config import Settings
from artifact_trust.manifests import ROOT_REF, analyze_manifests
from artifact_trust.sbom import build_cyclonedx, build_dependency_graph
from artifact_trust.scanners import run_offline_scans


def test_transitive_graph_and_cyclonedx(settings: Settings) -> None:
    root = settings.fixtures_root / "safe-app"
    analysis = analyze_manifests(root, settings.sandbox)
    assert [item.name for item in analysis.components] == ["alpha-lib", "transitive-lib"]
    assert sum(item.direct for item in analysis.components) == 1
    assert len(analysis.edges) == 2
    assert any(edge.source == ROOT_REF for edge in analysis.edges)
    graph = build_dependency_graph(analysis)
    assert graph["root"] == ROOT_REF
    sbom = build_cyclonedx(analysis, "a" * 64, "safe-app")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert len(sbom["components"]) == 2


def test_safe_fixture_has_no_offline_findings(settings: Settings) -> None:
    root = settings.fixtures_root / "safe-app"
    analysis = analyze_manifests(root, settings.sandbox)
    assert run_offline_scans(root, analysis, settings.sandbox) == ()


def test_vulnerability_is_found_offline(settings: Settings) -> None:
    root = settings.fixtures_root / "vulnerable-app"
    analysis = analyze_manifests(root, settings.sandbox)
    findings = run_offline_scans(root, analysis, settings.sandbox)
    vulnerability = next(item for item in findings if item.category == "vulnerability")
    assert vulnerability.advisory == "GHSA-35jh-r3h4-6jhm"
    assert vulnerability.severity.value == "high"


def test_secrets_are_redacted_and_disallowed_license_found(settings: Settings) -> None:
    root = settings.fixtures_root / "rejected-app"
    analysis = analyze_manifests(root, settings.sandbox)
    findings = run_offline_scans(root, analysis, settings.sandbox)
    secret = next(item for item in findings if item.category == "secret")
    assert secret.evidence.startswith("redacted sha256:")
    assert "AKIA" not in secret.model_dump_json()
    assert any(item.category == "license" and item.severity.value == "high" for item in findings)
    assert any(item.severity.value == "critical" for item in findings)


def test_unpinned_requirement_is_reported(settings: Settings) -> None:
    root = settings.fixtures_root / "unpinned-app"
    analysis = analyze_manifests(root, settings.sandbox)
    assert analysis.unpinned_dependencies == ("requests",)
    findings = run_offline_scans(root, analysis, settings.sandbox)
    assert any(item.category == "manifest" and "not pinned" in item.title for item in findings)
