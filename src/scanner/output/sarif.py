"""SARIF 2.1.0 output, so findings can surface in GitHub code scanning via
`github/codeql-action/upload-sarif` the same way a commercial SAST tool's
output would. See https://docs.oasis-open.org/sarif/sarif/v2.1.0/ for the
format; this module emits the subset GitHub's code-scanning ingestion
actually consumes (tool.driver.rules, results with ruleId/level/message/
physicalLocation)."""
from __future__ import annotations

from typing import Any

from scanner.findings import Finding
from taxonomy import TAXONOMY, Severity, get_taxonomy_entry

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "MCP Sentinel"
TOOL_INFORMATION_URI = "https://github.com/mcp-sentinel/mcp-sentinel"

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# security-severity is a float string GitHub's code-scanning UI uses to
# rank/badge results (0.0-10.0, CVSS-like); it is independent of `level`.
_SEVERITY_TO_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def findings_to_sarif(findings: list[Finding], tool_version: str = "0.1.0") -> dict[str, Any]:
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "version": tool_version,
                        "rules": [_rule_descriptor(entry.rule_id) for entry in TAXONOMY.values()],
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }


def _rule_descriptor(rule_id: str) -> dict[str, Any]:
    entry = get_taxonomy_entry(rule_id)
    tags = [f"OWASP-LLM:{item}" for item in entry.owasp_llm_top_10]
    if entry.owasp_top_10:
        tags.append(f"OWASP:{entry.owasp_top_10}")
    tags.extend(f"MITRE-ATT&CK:{item}" for item in entry.mitre_attack)
    tags.extend(f"STRIDE:{item}" for item in entry.stride)
    return {
        "id": rule_id,
        "name": entry.title.replace(" ", ""),
        "shortDescription": {"text": entry.title},
        "properties": {
            "security-severity": _SEVERITY_TO_SECURITY_SEVERITY[entry.default_severity],
            "tags": tags,
        },
    }


def _result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column,
                    },
                }
            }
        ],
    }
