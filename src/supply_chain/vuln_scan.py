"""Wraps `pip-audit` (PyPA's dependency vulnerability scanner, backed by
the OSV/PyPI advisory databases) rather than reimplementing a
vulnerability database -- that database is the actual hard problem here,
and `pip-audit` is the standard, actively-maintained tool for it. This
module owns process invocation, JSON parsing, and re-shaping the result
into MCP Sentinel's own report format; it is not itself a vulnerability
scanner.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 300


class PipAuditNotAvailable(RuntimeError):
    """Raised when `pip_audit` isn't importable in the running interpreter."""


class PipAuditFailed(RuntimeError):
    """Raised when `pip-audit` exits with an error status other than the
    "vulnerabilities found" status (1) or "clean" status (0)."""


def _ensure_pip_audit_importable() -> None:
    """Checks importability, not `shutil.which("pip-audit")`: resolving a
    `pip-audit` executable via PATH can find one installed for a *different*
    Python environment than the interpreter running MCP Sentinel itself (a
    real discrepancy seen on a machine with multiple Python installs), which
    would silently audit the wrong environment. Invoking it as
    `sys.executable -m pip_audit` (see `run_dependency_audit`) guarantees the
    audit targets the same environment the SBOM/license passes reflect."""
    if importlib.util.find_spec("pip_audit") is None:
        raise PipAuditNotAvailable(
            "pip-audit is not installed in this Python environment; install it with "
            "`pip install pip-audit` to enable dependency vulnerability scanning."
        )


def run_dependency_audit(
    requirements_path: Path | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Audit either a requirements file (`requirements_path` given) or the
    local Python environment (`requirements_path=None`) against public
    vulnerability advisory databases, and return a summarized report.

    Raises `PipAuditNotAvailable` if the tool isn't installed, and
    `PipAuditFailed` if it exits with a genuine error (as opposed to exit
    code 1, which `pip-audit` uses to mean "ran fine, found vulnerabilities").
    """
    _ensure_pip_audit_importable()
    args = [sys.executable, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off"]
    if requirements_path is not None:
        args.extend(["--requirement", str(requirements_path)])
    else:
        args.append("--local")

    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout_seconds)
    if result.returncode not in (0, 1):
        raise PipAuditFailed(f"pip-audit exited {result.returncode}: {result.stderr.strip()}")

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PipAuditFailed(f"pip-audit produced non-JSON output: {result.stdout[:500]!r}") from exc

    return summarize_pip_audit_payload(payload)


def summarize_pip_audit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Re-shape pip-audit's `{"dependencies": [{"name", "version", "vulns"}]}`
    payload into MCP Sentinel's report format. Extracted as its own
    function so tests can exercise the summarization logic against a
    canned payload without invoking the real `pip-audit` process."""
    dependencies = payload.get("dependencies", [])
    vulnerable = [dep for dep in dependencies if dep.get("vulns")]
    total_vulnerabilities = sum(len(dep.get("vulns", [])) for dep in dependencies)

    return {
        "total_dependencies_scanned": len(dependencies),
        "vulnerable_dependency_count": len(vulnerable),
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerable_dependencies": [
            {
                "name": dep["name"],
                "version": dep["version"],
                "vulnerabilities": [
                    {
                        "id": vuln.get("id"),
                        "fix_versions": vuln.get("fix_versions", []),
                        "aliases": vuln.get("aliases", []),
                        "description": vuln.get("description"),
                    }
                    for vuln in dep.get("vulns", [])
                ],
            }
            for dep in vulnerable
        ],
    }
