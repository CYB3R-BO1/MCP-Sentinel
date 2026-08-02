from __future__ import annotations

from scanner.findings import Finding
from taxonomy import Severity, get_taxonomy_entry

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def render_terminal_report(findings: list[Finding], scan_root: str) -> str:
    lines: list[str] = []
    lines.append("MCP Sentinel — Static Scan Report")
    lines.append("=" * 34)
    lines.append(f"Scanned: {scan_root}")

    counts = {sev: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    summary = ", ".join(f"{counts[sev]} {sev.value}" for sev in _SEVERITY_ORDER if counts[sev])
    lines.append(f"Findings: {len(findings)}" + (f" ({summary})" if summary else ""))
    lines.append("")

    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    ordered = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.file_path, f.line),
    )
    for finding in ordered:
        entry = get_taxonomy_entry(finding.rule_id)
        lines.append(
            f"[{finding.severity.value.upper()}] {finding.rule_id} "
            f"{finding.file_path}:{finding.line}:{finding.column}"
        )
        lines.append(f"  {finding.message}")
        taxonomy_bits = []
        if entry.owasp_top_10:
            taxonomy_bits.append(entry.owasp_top_10)
        taxonomy_bits.extend(entry.owasp_llm_top_10)
        taxonomy_bits.extend(entry.mitre_attack)
        if taxonomy_bits:
            lines.append(f"  Taxonomy: {' | '.join(taxonomy_bits)}")
        if finding.taint_trace:
            lines.append("  Trace:")
            for step in finding.taint_trace:
                lines.append(f"    {step}")
        lines.append("")

    return "\n".join(lines) + "\n"
