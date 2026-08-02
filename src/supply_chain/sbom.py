"""Generates a CycloneDX 1.5 JSON SBOM (https://cyclonedx.org/) either for
the currently-installed Python environment (this project) or from a
`requirements.txt`-style pinned dependency file (a scanned MCP server's
own requirements, when it has one).

Built directly on stdlib `importlib.metadata` rather than wrapping an
external SBOM-generator CLI: that avoids taking on a second tool's
version-compatibility surface (CycloneDX generator CLIs have changed
their subcommand shape across major versions) for a format simple enough
to emit correctly by hand. Trade-off recorded in WRITEUP.md.
"""
from __future__ import annotations

import importlib.metadata as metadata
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CYCLONEDX_SPEC_VERSION = "1.5"

_PINNED_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+-]*)$")


def _component(name: str, version: str) -> dict[str, str]:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name.lower()}@{version}",
    }


def _dedupe_sorted(components: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for component in sorted(components, key=lambda c: c["name"].lower()):
        key = (component["name"].lower(), component["version"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(component)
    return deduped


def _bom_document(
    components: list[dict[str, str]], root_name: str, root_version: str
) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": root_name, "version": root_version},
        },
        "components": components,
    }


def generate_sbom_for_environment(
    root_component_name: str = "mcp-sentinel", root_component_version: str = "0.1.0"
) -> dict[str, Any]:
    """SBOM covering every distribution installed in the current Python
    environment -- used for MCP Sentinel's own SBOM."""
    components = [
        _component(dist.metadata["Name"] or dist.name, dist.version)
        for dist in metadata.distributions()
        if dist.metadata["Name"]
    ]
    return _bom_document(_dedupe_sorted(components), root_component_name, root_component_version)


def generate_sbom_for_requirements(
    requirements_path: Path,
    root_component_name: str | None = None,
    root_component_version: str = "0.0.0",
) -> dict[str, Any]:
    """SBOM built from a `requirements.txt`-style file's exactly-pinned
    (`name==version`) lines -- used for a scanned MCP server's own
    dependencies. Unpinned or otherwise complex specifiers (`>=`, extras,
    VCS URLs, `-r other.txt` includes) are skipped: an SBOM entry with no
    verifiable version isn't more useful than no entry, and a partial SBOM
    with all *pinned* dependencies present is still meaningfully accurate."""
    components: list[dict[str, str]] = []
    for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        match = _PINNED_REQUIREMENT_RE.match(line)
        if not match:
            continue
        name, version = match.groups()
        components.append(_component(name, version))

    root_name = root_component_name or requirements_path.parent.name or requirements_path.stem
    return _bom_document(_dedupe_sorted(components), root_name, root_component_version)
