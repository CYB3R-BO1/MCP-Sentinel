"""Combines SBOM generation, dependency vulnerability scanning, and license
checking into one report and a terminal renderer for it -- the
supply-chain equivalent of `scanner.scan`/`scanner.output.terminal`."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from supply_chain.license_check import check_licenses
from supply_chain.sbom import generate_sbom_for_environment, generate_sbom_for_requirements
from supply_chain.vuln_scan import PipAuditNotAvailable, run_dependency_audit


def generate_supply_chain_report(
    requirements_path: Path | None = None,
    skip_vuln_scan: bool = False,
) -> dict[str, Any]:
    sbom = (
        generate_sbom_for_requirements(requirements_path)
        if requirements_path is not None
        else generate_sbom_for_environment()
    )
    license_report = check_licenses()

    dependency_audit: dict[str, Any] | None
    if skip_vuln_scan:
        dependency_audit = None
    else:
        try:
            dependency_audit = run_dependency_audit(requirements_path)
        except PipAuditNotAvailable as exc:
            dependency_audit = {"error": str(exc)}

    return {
        "sbom": sbom,
        "license_check": license_report,
        "dependency_audit": dependency_audit,
    }


def render_terminal_report(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("MCP Sentinel - Supply Chain Report")
    lines.append("=" * 35)

    sbom = report["sbom"]
    lines.append(f"SBOM: {len(sbom['components'])} component(s) for {sbom['metadata']['component']['name']}")

    licenses = report["license_check"]
    lines.append(
        f"Licenses: {licenses['total_packages']} package(s) - "
        f"{licenses['permissive_count']} permissive, "
        f"{licenses['copyleft_count']} copyleft, "
        f"{licenses['unknown_count']} unknown"
    )
    if licenses["copyleft_count"]:
        lines.append("  Copyleft-licensed packages:")
        for entry in licenses["flagged"]:
            if entry["category"] == "copyleft":
                lines.append(f"    - {entry['name']} {entry['version']}: {entry['license']}")

    audit = report["dependency_audit"]
    lines.append("")
    if audit is None:
        lines.append("Dependency vulnerability audit: skipped")
    elif "error" in audit:
        lines.append(f"Dependency vulnerability audit: unavailable ({audit['error']})")
    else:
        lines.append(
            f"Dependency vulnerability audit: {audit['total_vulnerabilities']} "
            f"vulnerabilit{'y' if audit['total_vulnerabilities'] == 1 else 'ies'} across "
            f"{audit['vulnerable_dependency_count']} of {audit['total_dependencies_scanned']} "
            "dependencies"
        )
        for dep in audit["vulnerable_dependencies"]:
            ids = ", ".join(v["id"] for v in dep["vulnerabilities"])
            lines.append(f"  - {dep['name']} {dep['version']}: {ids}")

    return "\n".join(lines) + "\n"
