"""Flags a tool-decorated function whose docstring (the text an MCP client
sends to the model as the tool's description) contains instruction-like
phrasing. A tool description is model-visible content an attacker who can
influence a server's configuration -- or a compromised/malicious MCP
server the agent connects to -- can weaponize as a prompt-injection vector,
independent of any single tool call's arguments (OWASP LLM01)."""
from __future__ import annotations

import ast
import re

from scanner.ast_utils import is_tool_decorated
from scanner.findings import Finding
from scanner.project import Project
from scanner.structural_rules.base import StructuralRule
from taxonomy import get_taxonomy_entry

_SUSPICIOUS_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+|any\s+|previous\s+)*instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(?:the\s+|any\s+|all\s+|previous\s+|prior\s+)*instructions", re.IGNORECASE),
    re.compile(r"\bsystem:\s", re.IGNORECASE),
    re.compile(r"you\s+must\s+(now\s+|immediately\s+)?", re.IGNORECASE),
    re.compile(r"override\s+(your\s+|any\s+|all\s+)?(rules|instructions|guidelines)", re.IGNORECASE),
    re.compile(r"do\s+not\s+(tell|inform|mention|reveal)", re.IGNORECASE),
]


class ToolDescriptionInjectionRule(StructuralRule):
    rule_id = "MCP-SENT-007"

    def check_project(self, project: Project) -> list[Finding]:
        findings: list[Finding] = []
        entry = get_taxonomy_entry(self.rule_id)

        for source_file in project.files:
            for node in ast.walk(source_file.tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not is_tool_decorated(node):
                    continue
                docstring = ast.get_docstring(node)
                if not docstring:
                    continue
                for pattern in _SUSPICIOUS_PATTERNS:
                    match = pattern.search(docstring)
                    if match:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=entry.default_severity,
                                message=(
                                    f"Tool '{node.name}''s description contains "
                                    f"instruction-like text ({match.group(0)!r}), which is "
                                    "sent verbatim to the model and can be weaponized as a "
                                    "prompt-injection vector."
                                ),
                                file_path=source_file.file_path,
                                line=node.lineno,
                                column=node.col_offset + 1,
                            )
                        )
                        break  # one finding per tool is enough signal
        return findings
