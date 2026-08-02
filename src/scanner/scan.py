"""Top-level entrypoint that runs every taint sink rule and every
structural rule over a scan root and returns one combined, sorted list of
findings. This is what the CLI (`scanner.cli`) and the output formatters
build on."""
from __future__ import annotations

from pathlib import Path

from scanner.findings import Finding
from scanner.project import load_project
from scanner.rules import DEFAULT_SINK_RULES
from scanner.structural_rules import DEFAULT_STRUCTURAL_RULES
from scanner.taint.engine import analyze_project


def run_scan(root: Path) -> list[Finding]:
    project = load_project(root)
    findings: list[Finding] = list(analyze_project(project, DEFAULT_SINK_RULES))
    for rule in DEFAULT_STRUCTURAL_RULES:
        findings.extend(rule.check_project(project))
    return sorted(findings, key=lambda f: (f.file_path, f.line, f.rule_id))
