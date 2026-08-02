def test_flags_tainted_arg_reaching_shell_true(scan_source):
    findings = scan_source(
        """
import subprocess

def run_command(filename):
    result = subprocess.run(f"cat {filename}", shell=True, capture_output=True)
    return result.stdout
"""
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "MCP-SENT-005"
    assert finding.line == 5
    assert "run_command" in findings[0].taint_trace[0]


def test_does_not_flag_shell_false(scan_source):
    findings = scan_source(
        """
import subprocess

def run_command(filename):
    result = subprocess.run(["cat", filename], shell=False, capture_output=True)
    return result.stdout
"""
    )
    assert findings == []


def test_flags_os_system(scan_source):
    findings = scan_source(
        """
import os

def run_command(filename):
    os.system(f"cat {filename}")
"""
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-005"


def test_does_not_flag_untainted_command(scan_source):
    findings = scan_source(
        """
import subprocess

def list_workspace():
    subprocess.run("ls -la", shell=True, capture_output=True)
"""
    )
    assert findings == []
