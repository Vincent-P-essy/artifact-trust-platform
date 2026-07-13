"""Deterministic manifest and lockfile analysis."""

from __future__ import annotations

import json
import tomllib
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

from packaging.requirements import InvalidRequirement, Requirement

from artifact_trust.models import Component, DependencyEdge, ManifestAnalysis, SandboxPolicy
from artifact_trust.util import iter_safe_files

ROOT_REF = "urn:artifact-trust:root"


def _scope(entry: dict[str, object]) -> str:
    if entry.get("dev") is True:
        return "development"
    if entry.get("optional") is True:
        return "optional"
    return "required"


def _npm_purl(name: str, version: str) -> str:
    return f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"


def _pypi_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{quote(name.lower().replace('_', '-'), safe='-')}@{quote(version, safe='')}"


def _npm_component(
    package_path: str,
    entry: dict[str, object],
    direct_names: set[str],
    manifest: str,
) -> Component | None:
    name_value = entry.get("name")
    if isinstance(name_value, str):
        name = name_value
    else:
        marker = "/node_modules/"
        name = (
            package_path.rsplit(marker, 1)[-1]
            if marker in package_path
            else package_path.removeprefix("node_modules/")
        )
    version = entry.get("version")
    if not name or not isinstance(version, str) or not version:
        return None
    license_value = entry.get("license")
    licenses: tuple[str, ...]
    if isinstance(license_value, str):
        licenses = (license_value.strip(),) if license_value.strip() else ()
    elif isinstance(license_value, list):
        licenses = tuple(sorted(str(item).strip() for item in license_value if str(item).strip()))
    else:
        licenses = ()
    purl = _npm_purl(name, version)
    path_token = quote(package_path, safe="")
    return Component(
        bom_ref=f"{purl}#{path_token}",
        name=name,
        version=version,
        ecosystem="npm",
        purl=purl,
        scope=_scope(entry),
        direct=name in direct_names and package_path == f"node_modules/{name}",
        licenses=licenses,
        source_manifest=manifest,
    )


def _resolve_npm_dependency(parent: str, name: str, paths: set[str]) -> str | None:
    if not parent:
        candidate = f"node_modules/{name}"
        return candidate if candidate in paths else None
    current = parent
    while current:
        nested = f"{current}/node_modules/{name}"
        if nested in paths:
            return nested
        if "/node_modules/" not in current:
            break
        current = current.rsplit("/node_modules/", 1)[0]
    top = f"node_modules/{name}"
    return top if top in paths else None


def _parse_package_lock(
    root: Path, relative: str
) -> tuple[list[Component], list[DependencyEdge], list[str], list[str]]:
    data = json.loads((root / relative).read_text(encoding="utf-8"))
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return [], [], [], [f"{relative}: only package-lock v2/v3 packages maps are supported"]
    root_entry = packages.get("")
    direct_names: set[str] = set()
    if isinstance(root_entry, dict):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            values = root_entry.get(section)
            if isinstance(values, dict):
                direct_names.update(str(name) for name in values)
    path_entries = {
        str(package_path): entry
        for package_path, entry in packages.items()
        if package_path and isinstance(entry, dict)
    }
    components_by_path: dict[str, Component] = {}
    for package_path, entry in sorted(path_entries.items()):
        component = _npm_component(package_path, entry, direct_names, relative)
        if component:
            components_by_path[package_path] = component

    edges: set[tuple[str, str]] = set()
    warnings: list[str] = []
    for name in sorted(direct_names):
        resolved = _resolve_npm_dependency("", name, set(path_entries))
        if resolved and resolved in components_by_path:
            edges.add((ROOT_REF, components_by_path[resolved].bom_ref))
        else:
            warnings.append(f"{relative}: unresolved direct dependency {name}")
    for package_path, entry in sorted(path_entries.items()):
        parent = components_by_path.get(package_path)
        dependencies = entry.get("dependencies")
        if parent is None or not isinstance(dependencies, dict):
            continue
        for name in sorted(str(item) for item in dependencies):
            resolved = _resolve_npm_dependency(package_path, name, set(path_entries))
            if resolved and resolved in components_by_path:
                edges.add((parent.bom_ref, components_by_path[resolved].bom_ref))
            else:
                warnings.append(f"{relative}: unresolved dependency {parent.name} -> {name}")
    return (
        list(components_by_path.values()),
        [DependencyEdge(source=source, target=target) for source, target in sorted(edges)],
        [],
        warnings,
    )


def _parse_requirement_lines(
    text: str, relative: str
) -> tuple[list[Component], list[DependencyEdge], list[str], list[str]]:
    components: list[Component] = []
    edges: list[DependencyEdge] = []
    unpinned: list[str] = []
    warnings: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", "http:", "https:", "git+")):
            unpinned.append(line.split()[0])
            warnings.append(
                f"{relative}:{line_number}: non-registry or option requirement not resolved"
            )
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            warnings.append(f"{relative}:{line_number}: invalid requirement")
            unpinned.append(line)
            continue
        pins = [
            item
            for item in requirement.specifier
            if item.operator == "==" and "*" not in item.version
        ]
        if len(pins) != 1 or len(list(requirement.specifier)) != 1:
            unpinned.append(requirement.name)
            continue
        version = pins[0].version
        purl = _pypi_purl(requirement.name, version)
        component = Component(
            bom_ref=purl,
            name=requirement.name,
            version=version,
            ecosystem="pypi",
            purl=purl,
            direct=True,
            licenses=(),
            source_manifest=relative,
        )
        components.append(component)
        edges.append(DependencyEdge(source=ROOT_REF, target=purl))
    return components, edges, unpinned, warnings


def _parse_pyproject(
    root: Path, relative: str
) -> tuple[list[Component], list[DependencyEdge], list[str], list[str]]:
    data = tomllib.loads((root / relative).read_text(encoding="utf-8"))
    project = data.get("project", {})
    dependencies = project.get("dependencies", []) if isinstance(project, dict) else []
    if not isinstance(dependencies, list):
        return [], [], [], [f"{relative}: project.dependencies must be a list"]
    return _parse_requirement_lines("\n".join(str(item) for item in dependencies), relative)


def analyze_manifests(root: Path, limits: SandboxPolicy) -> ManifestAnalysis:
    recognized: list[str] = []
    components: dict[str, Component] = {}
    edge_pairs: set[tuple[str, str]] = set()
    unpinned: set[str] = set()
    warnings: set[str] = set()
    parsers = {
        "package-lock.json": _parse_package_lock,
        "pyproject.toml": _parse_pyproject,
    }
    for relative, path, _ in iter_safe_files(root, limits):
        basename = path.name
        parser = parsers.get(basename)
        if parser is None and not (
            basename.startswith("requirements") and basename.endswith((".txt", ".lock"))
        ):
            continue
        recognized.append(relative)
        if parser is None:
            result = _parse_requirement_lines(path.read_text(encoding="utf-8"), relative)
        else:
            result = parser(root, relative)
        parsed_components, parsed_edges, parsed_unpinned, parsed_warnings = result
        for component in parsed_components:
            components.setdefault(component.bom_ref, component)
        edge_pairs.update((edge.source, edge.target) for edge in parsed_edges)
        unpinned.update(parsed_unpinned)
        warnings.update(parsed_warnings)

    return ManifestAnalysis(
        manifests=tuple(sorted(recognized)),
        components=tuple(sorted(components.values(), key=lambda item: item.bom_ref)),
        edges=tuple(DependencyEdge(source=a, target=b) for a, b in sorted(edge_pairs)),
        unpinned_dependencies=tuple(sorted(unpinned)),
        warnings=tuple(sorted(warnings)),
    )


def adjacency(analysis: ManifestAnalysis) -> dict[str, list[str]]:
    graph: defaultdict[str, list[str]] = defaultdict(list)
    graph[ROOT_REF]
    for component in analysis.components:
        graph[component.bom_ref]
    for edge in analysis.edges:
        graph[edge.source].append(edge.target)
    return {node: sorted(targets) for node, targets in sorted(graph.items())}
