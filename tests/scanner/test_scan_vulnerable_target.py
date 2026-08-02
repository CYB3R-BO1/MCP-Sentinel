"""Runs the full scanner (taint engine + structural rules) against
`vulnerable_target`, MCP Sentinel's own fixture, and asserts it finds every
vulnerability class THREAT_MODEL.md documents as statically detectable.
This is the scanner's own "does it actually work" proof, parallel to how
sub-project 1's tests prove the vulnerabilities themselves are real."""
from pathlib import Path

from scanner.scan import run_scan

VULNERABLE_TARGET_ROOT = Path(__file__).parents[2] / "src" / "vulnerable_target"


def _findings():
    return run_scan(VULNERABLE_TARGET_ROOT)


def test_finds_all_seven_statically_detectable_rule_classes():
    findings = _findings()
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {
        "MCP-SENT-001",  # excessive permission scope
        "MCP-SENT-002",  # SSRF
        "MCP-SENT-003",  # path traversal
        "MCP-SENT-004",  # SQL injection
        "MCP-SENT-005",  # command injection
        "MCP-SENT-006",  # missing rate limit/auth
    }
    # MCP-SENT-007 (tool description injection) correctly does NOT fire --
    # vulnerable_target's tool docstrings are clean; that's covered by a
    # dedicated fixture in test_structural_tool_description_injection.py.


def test_ssrf_finding_points_at_fetch_url_tool():
    findings = [f for f in _findings() if f.rule_id == "MCP-SENT-002"]
    assert len(findings) == 1
    assert findings[0].file_path == "tools/fetch_url.py"


def test_sql_injection_finding_points_at_query_db_tool():
    findings = [f for f in _findings() if f.rule_id == "MCP-SENT-004"]
    assert len(findings) == 1
    assert findings[0].file_path == "tools/query_db.py"
    assert findings[0].severity.value == "critical"


def test_command_injection_finding_points_at_run_command_tool():
    findings = [f for f in _findings() if f.rule_id == "MCP-SENT-005"]
    assert len(findings) == 1
    assert findings[0].file_path == "tools/run_command.py"
    assert findings[0].severity.value == "critical"


def test_path_traversal_finding_points_at_read_file_tool():
    findings = [f for f in _findings() if f.rule_id == "MCP-SENT-003"]
    assert len(findings) == 1
    assert findings[0].file_path == "tools/read_file.py"


def test_excessive_permission_scope_flags_all_four_tools():
    findings = [f for f in _findings() if f.rule_id == "MCP-SENT-001"]
    flagged_tools = {f.message.split("'")[1] for f in findings}
    assert flagged_tools == {"read_file", "fetch_url", "query_db", "run_command"}


def test_missing_rate_limit_finding_points_at_server_file():
    findings = [f for f in _findings() if f.rule_id == "MCP-SENT-006"]
    assert len(findings) == 1
    assert findings[0].file_path == "server.py"


def test_every_finding_severity_matches_its_taxonomy_default():
    from taxonomy import get_taxonomy_entry

    for finding in _findings():
        entry = get_taxonomy_entry(finding.rule_id)
        assert finding.severity == entry.default_severity
