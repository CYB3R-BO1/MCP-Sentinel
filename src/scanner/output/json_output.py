from __future__ import annotations

from typing import Any

from scanner.findings import Finding
from taxonomy import Severity, get_taxonomy_entry

SCHEMA_VERSION = "1.0"


def findings_to_json(findings: list[Finding], scan_root: str) -> dict[str, Any]:
    counts = {sev.value: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "scan_root": scan_root,
        "summary": {
            "total": len(findings),
            "by_severity": counts,
        },
        "findings": [_finding_to_dict(f) for f in findings],
    }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    entry = get_taxonomy_entry(finding.rule_id)
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "message": finding.message,
        "file": finding.file_path,
        "line": finding.line,
        "column": finding.column,
        "taint_trace": list(finding.taint_trace),
        "taxonomy": {
            "title": entry.title,
            "stride": list(entry.stride),
            "owasp_top_10": entry.owasp_top_10,
            "owasp_llm_top_10": list(entry.owasp_llm_top_10),
            "mitre_attack": list(entry.mitre_attack),
            "threat_model_class": entry.threat_model_class,
        },
    }
