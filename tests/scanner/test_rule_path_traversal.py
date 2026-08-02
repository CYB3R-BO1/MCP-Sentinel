def test_flags_pathlib_join_with_tainted_segment(scan_source):
    findings = scan_source(
        """
from pathlib import Path

SANDBOX_ROOT = Path("/sandbox")

def read_file(path):
    target = SANDBOX_ROOT / path
    return target.read_text()
"""
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-003"


def test_flags_builtin_open_with_tainted_path(scan_source):
    findings = scan_source(
        """
def read_file(path):
    with open(path) as f:
        return f.read()
"""
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-003"


def test_does_not_flag_after_resolve_sanitizer(scan_source):
    findings = scan_source(
        """
from pathlib import Path

SANDBOX_ROOT = Path("/sandbox")

def read_file(path):
    target = (SANDBOX_ROOT / path).resolve()
    return target.read_text()
"""
    )
    assert findings == []


def test_does_not_flag_untainted_constant_path(scan_source):
    findings = scan_source(
        """
from pathlib import Path

def read_readme():
    return (Path("/sandbox") / "README.txt").read_text()
"""
    )
    assert findings == []
