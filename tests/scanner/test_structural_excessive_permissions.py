from scanner.project import load_project
from scanner.structural_rules import ExcessivePermissionScopeRule


def _check(tmp_path, code: str):
    (tmp_path / "permissions.py").write_text(code, encoding="utf-8")
    project = load_project(tmp_path)
    return ExcessivePermissionScopeRule().check_project(project)


def test_flags_wildcard_scope(tmp_path):
    findings = _check(
        tmp_path,
        """
TOOL_PERMISSIONS = {
    "read_file": {
        "scopes": ["fs:read:*"],
        "declared_purpose": "read files within the workspace sandbox",
    },
}
""",
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-001"
    assert "wildcard" in findings[0].message


def test_flags_write_scope_with_read_only_purpose(tmp_path):
    findings = _check(
        tmp_path,
        """
TOOL_PERMISSIONS = {
    "query_db": {
        "scopes": ["db:read", "db:write"],
        "declared_purpose": "run read-only reporting queries against the users table",
    },
}
""",
    )
    assert len(findings) == 1
    assert "write access" in findings[0].message


def test_flags_exec_scope_with_unrelated_purpose(tmp_path):
    findings = _check(
        tmp_path,
        """
TOOL_PERMISSIONS = {
    "run_command": {
        "scopes": ["exec:*"],
        "declared_purpose": "list files present in the workspace sandbox",
    },
}
""",
    )
    # Both the wildcard reason and the exec-purpose-mismatch reason apply.
    assert len(findings) == 2
    assert {f.rule_id for f in findings} == {"MCP-SENT-001"}


def test_does_not_flag_narrowly_scoped_tool(tmp_path):
    findings = _check(
        tmp_path,
        """
TOOL_PERMISSIONS = {
    "get_time": {
        "scopes": ["clock:read"],
        "declared_purpose": "return the current server time",
    },
}
""",
    )
    assert findings == []


def test_flags_wildcard_scope_in_an_annotated_assignment(tmp_path):
    findings = _check(
        tmp_path,
        """
from typing import TypedDict


class ToolPermission(TypedDict):
    scopes: list[str]
    declared_purpose: str


TOOL_PERMISSIONS: dict[str, ToolPermission] = {
    "read_file": {
        "scopes": ["fs:read:*"],
        "declared_purpose": "read files within the workspace sandbox",
    },
}
""",
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-001"


def test_ignores_dicts_that_are_not_permission_manifests(tmp_path):
    findings = _check(
        tmp_path,
        """
CONFIG = {
    "timeout": {"value": 30, "unit": "seconds"},
}
""",
    )
    assert findings == []
