from scanner.findings import Finding
from scanner.output.terminal import render_terminal_report
from taxonomy import Severity


def test_no_findings_reports_clean():
    output = render_terminal_report([], "src/vulnerable_target")
    assert "Findings: 0" in output
    assert "No findings." in output


def test_reports_severity_counts_and_finding_details():
    finding = Finding(
        rule_id="MCP-SENT-005",
        severity=Severity.CRITICAL,
        message="Unsanitized input reaches a shell execution sink",
        file_path="tools/run_command.py",
        line=14,
        column=5,
        taint_trace=("parameter 'filename'", "-> sink at tools/run_command.py:14"),
    )
    output = render_terminal_report([finding], "src/vulnerable_target")

    assert "Findings: 1 (1 critical)" in output
    assert "[CRITICAL] MCP-SENT-005 tools/run_command.py:14:5" in output
    assert "Unsanitized input reaches a shell execution sink" in output
    assert "A03:2021 Injection" in output
    assert "parameter 'filename'" in output


def test_orders_critical_before_lower_severity():
    low = Finding(
        rule_id="MCP-SENT-001",
        severity=Severity.MEDIUM,
        message="low-ish finding",
        file_path="a.py",
        line=1,
        column=1,
    )
    high = Finding(
        rule_id="MCP-SENT-005",
        severity=Severity.CRITICAL,
        message="critical finding",
        file_path="z.py",
        line=1,
        column=1,
    )
    output = render_terminal_report([low, high], "root")
    assert output.index("critical finding") < output.index("low-ish finding")
