from scanner.project import load_project
from scanner.structural_rules import MissingRateLimitOrAuthRule


def _check(tmp_path, code: str):
    (tmp_path / "server.py").write_text(code, encoding="utf-8")
    project = load_project(tmp_path)
    return MissingRateLimitOrAuthRule().check_project(project)


def test_flags_tool_file_with_no_protective_construct(tmp_path):
    findings = _check(
        tmp_path,
        """
from mcp.server import MCPServer

mcp_app = MCPServer("demo")

@mcp_app.tool()
def read_file(path: str) -> str:
    return open(path).read()
""",
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-006"
    assert "read_file" in findings[0].message


def test_does_not_flag_file_mentioning_rate_limiting(tmp_path):
    findings = _check(
        tmp_path,
        """
from mcp.server import MCPServer

mcp_app = MCPServer("demo")
rate_limiter = object()

@mcp_app.tool()
def read_file(path: str) -> str:
    return open(path).read()
""",
    )
    assert findings == []


def test_does_not_flag_a_file_with_no_tools(tmp_path):
    findings = _check(
        tmp_path,
        """
def helper(x):
    return x + 1
""",
    )
    assert findings == []
