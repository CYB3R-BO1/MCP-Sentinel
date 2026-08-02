"""Flags a tool permission manifest -- a module-level dict-of-dicts where
each entry has "scopes" (list[str]) and "declared_purpose" (str) keys, the
shape `vulnerable_target/permissions.py` uses -- where a tool's granted
scopes exceed what its own declared purpose calls for. This is a coarse,
keyword-based heuristic (a real static analyzer can't know a tool's true
required privilege from a purpose string alone), tuned to catch the
patterns real MCP servers actually ship: wildcard scopes, write access
granted to a "read-only" tool, and unrestricted execution granted to a
tool whose purpose never mentions running anything.
"""
from __future__ import annotations

import ast

from scanner.findings import Finding
from scanner.project import Project
from scanner.structural_rules.base import StructuralRule
from taxonomy import get_taxonomy_entry


def _excessive_scope_reasons(scopes: list[str], purpose: str) -> list[str]:
    reasons: list[str] = []
    purpose_lower = purpose.lower()

    for scope in scopes:
        if scope.endswith("*"):
            reasons.append(f"scope '{scope}' grants unrestricted wildcard access")

    if any(scope.endswith(":write") or scope.split(":")[-1] == "write" for scope in scopes) and (
        "read-only" in purpose_lower or "read only" in purpose_lower
    ):
        reasons.append("a scope grants write access but the declared purpose is read-only")

    if any(scope.startswith("exec:") for scope in scopes) and not any(
        keyword in purpose_lower for keyword in ("exec", "shell", "run", "command")
    ):
        reasons.append(
            "a scope grants arbitrary execution but the declared purpose doesn't mention "
            "running commands"
        )

    return reasons


class ExcessivePermissionScopeRule(StructuralRule):
    rule_id = "MCP-SENT-001"

    def check_project(self, project: Project) -> list[Finding]:
        findings: list[Finding] = []
        entry = get_taxonomy_entry(self.rule_id)

        for source_file in project.files:
            for stmt in source_file.tree.body:
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and isinstance(stmt.value, ast.Dict):
                    manifest_dict = stmt.value
                else:
                    continue
                for tool_key, tool_value in zip(manifest_dict.keys, manifest_dict.values):
                    if tool_key is None or not isinstance(tool_value, ast.Dict):
                        continue
                    try:
                        tool_name = ast.literal_eval(tool_key)
                        permission = ast.literal_eval(tool_value)
                    except (ValueError, SyntaxError, TypeError):
                        continue
                    if not (
                        isinstance(permission, dict)
                        and isinstance(permission.get("scopes"), list)
                        and isinstance(permission.get("declared_purpose"), str)
                    ):
                        continue

                    reasons = _excessive_scope_reasons(
                        permission["scopes"], permission["declared_purpose"]
                    )
                    for reason in reasons:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=entry.default_severity,
                                message=f"Tool '{tool_name}' has excessive permission scope: {reason}.",
                                file_path=source_file.file_path,
                                line=tool_value.lineno,
                                column=tool_value.col_offset + 1,
                            )
                        )
        return findings
