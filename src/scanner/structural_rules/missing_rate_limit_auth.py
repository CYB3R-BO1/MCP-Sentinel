"""Flags a file that registers MCP tool endpoints (a function decorated
with something ending in `.tool` / `@tool`) but contains no token anywhere
in that file suggesting rate limiting or authentication. This is
necessarily a coarse, single-file heuristic -- a real deployment might
enforce both in a separate layer (a reverse proxy, an API gateway, MCP
Sentinel's own runtime proxy in sub-project 4) -- so this rule's finding
message says so explicitly and should be read as "not obviously present
in this file", not "absent from the deployment"."""
from __future__ import annotations

import ast

from scanner.ast_utils import is_tool_decorated
from scanner.findings import Finding
from scanner.project import Project
from scanner.structural_rules.base import StructuralRule
from taxonomy import get_taxonomy_entry

_PROTECTIVE_TOKEN_SUBSTRINGS = (
    "ratelimit",
    "rate_limit",
    "throttle",
    "auth",
    "depends",
    "apikey",
    "api_key",
    "bearer",
    "token_required",
)


def _file_mentions_a_protective_token(source: str) -> bool:
    lowered = source.lower()
    return any(token in lowered for token in _PROTECTIVE_TOKEN_SUBSTRINGS)


class MissingRateLimitOrAuthRule(StructuralRule):
    rule_id = "MCP-SENT-006"

    def check_project(self, project: Project) -> list[Finding]:
        findings: list[Finding] = []
        entry = get_taxonomy_entry(self.rule_id)

        for source_file in project.files:
            tool_functions = [
                node
                for node in ast.walk(source_file.tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and is_tool_decorated(node)
            ]
            if not tool_functions:
                continue
            if _file_mentions_a_protective_token(source_file.source):
                continue

            tool_names = ", ".join(sorted(n.name for n in tool_functions))
            first = min(tool_functions, key=lambda n: n.lineno)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=entry.default_severity,
                    message=(
                        f"This file registers {len(tool_functions)} tool endpoint(s) "
                        f"({tool_names}) with no rate-limiting or authentication construct "
                        "detected anywhere in the file."
                    ),
                    file_path=source_file.file_path,
                    line=first.lineno,
                    column=first.col_offset + 1,
                )
            )
        return findings
