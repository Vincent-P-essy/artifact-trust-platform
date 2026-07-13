"""CycloneDX 1.6 JSON generation."""

from __future__ import annotations

import uuid
from typing import Any

from artifact_trust import __version__
from artifact_trust.manifests import ROOT_REF, adjacency
from artifact_trust.models import ManifestAnalysis


def build_cyclonedx(
    analysis: ManifestAnalysis, source_digest: str, source_name: str
) -> dict[str, Any]:
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"artifact-trust:{source_digest}")
    components: list[dict[str, Any]] = []
    for component in analysis.components:
        item: dict[str, Any] = {
            "type": "library",
            "bom-ref": component.bom_ref,
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "scope": "required" if component.scope == "required" else "optional",
            "properties": [
                {"name": "artifact-trust:direct", "value": str(component.direct).lower()},
                {"name": "artifact-trust:manifest", "value": component.source_manifest},
                {"name": "artifact-trust:scope", "value": component.scope},
            ],
        }
        if component.licenses:
            item["licenses"] = [{"license": {"id": value}} for value in component.licenses]
        components.append(item)
    graph = adjacency(analysis)
    dependencies = [
        {"ref": reference, "dependsOn": targets} for reference, targets in graph.items()
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": "1970-01-01T00:00:00Z",
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "artifact-trust-platform",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": ROOT_REF,
                "name": source_name,
                "version": source_digest[:12],
                "hashes": [{"alg": "SHA-256", "content": source_digest}],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }


def build_dependency_graph(analysis: ManifestAnalysis) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "root": ROOT_REF,
        "nodes": [
            {
                "id": component.bom_ref,
                "name": component.name,
                "version": component.version,
                "ecosystem": component.ecosystem,
                "direct": component.direct,
            }
            for component in analysis.components
        ],
        "edges": [edge.model_dump(mode="json") for edge in analysis.edges],
        "adjacency": adjacency(analysis),
    }
