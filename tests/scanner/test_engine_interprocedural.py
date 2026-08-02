"""Proves the taint engine follows a value across a function-call boundary
into a different file -- the exact `tool_input -> string formatting ->
shell()` chain described in the project's requirements -- rather than only
catching a vulnerability when source and sink sit in the same function."""


def test_taint_propagates_through_a_helper_function_in_another_file(tmp_path):
    from scanner.project import load_project
    from scanner.rules import DEFAULT_SINK_RULES
    from scanner.taint.engine import analyze_project

    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "run_command.py").write_text(
        """
import subprocess

def _run_command(filename):
    result = subprocess.run(f"cat {filename}", shell=True, capture_output=True)
    return result.stdout
""",
        encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        """
from tools.run_command import _run_command

def run_command(filename):
    return _run_command(filename)
""",
        encoding="utf-8",
    )

    project = load_project(tmp_path)
    findings = analyze_project(project, DEFAULT_SINK_RULES)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "MCP-SENT-005"
    assert finding.file_path == "tools/run_command.py"
    assert finding.line == 5

    trace_text = " ".join(finding.taint_trace)
    assert "run_command" in trace_text
    assert "_run_command" in trace_text
    assert "server.py" in trace_text


def test_deeper_three_hop_chain_is_still_traced(tmp_path):
    from scanner.project import load_project
    from scanner.rules import DEFAULT_SINK_RULES
    from scanner.taint.engine import analyze_project

    (tmp_path / "a.py").write_text(
        """
def entrypoint(user_value):
    return middle(user_value)
""",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        """
def middle(v):
    return sink_wrapper(v)
""",
        encoding="utf-8",
    )
    (tmp_path / "c.py").write_text(
        """
import subprocess

def sink_wrapper(cmd_part):
    subprocess.run(f"echo {cmd_part}", shell=True)
""",
        encoding="utf-8",
    )

    project = load_project(tmp_path)
    findings = analyze_project(project, DEFAULT_SINK_RULES)

    assert len(findings) == 1
    assert findings[0].file_path == "c.py"
    assert findings[0].rule_id == "MCP-SENT-005"
