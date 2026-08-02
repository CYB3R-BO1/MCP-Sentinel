"""Discovers Python source files under a scan root and gives the taint
engine a lightweight, name-based way to follow a function call to its
definition even when that definition lives in a different file.

Resolution is intentionally simple: it indexes every top-level (module- or
class-level) function definition by its bare name. A call to `foo(x)` is
resolved to a defined `foo` if exactly one such function exists anywhere
under the scan root. This is not a full import-graph resolver -- two
same-named functions in unrelated modules will not resolve -- but it is
sufficient for the common case this scanner targets: a small MCP server
package where each tool function has a distinct name. This trade-off is
documented in WRITEUP.md.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FunctionDef:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file_path: str  # POSIX-style, relative to the scan root


@dataclass
class SourceFile:
    file_path: str  # POSIX-style, relative to the scan root
    tree: ast.Module
    source: str


@dataclass
class Project:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    _functions_by_name: dict[str, list[FunctionDef]] = field(default_factory=dict)

    def resolve_call_target(self, func_name: str) -> FunctionDef | None:
        """Return the unique function definition named `func_name` under
        the scan root, or None if there are zero or multiple candidates."""
        candidates = self._functions_by_name.get(func_name, [])
        if len(candidates) == 1:
            return candidates[0]
        return None

    def index_function(self, func_def: FunctionDef) -> None:
        self._functions_by_name.setdefault(func_def.node.name, []).append(func_def)


def _iter_all_function_defs(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append(node)
    return found


def load_project(root: Path) -> Project:
    """Parse every `*.py` file under `root` into a `Project`."""
    project = Project(root=root)
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git", "__pycache__", ".venv", "venv"} for part in path.parts):
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue
        relative = path.relative_to(root).as_posix()
        project.files.append(SourceFile(file_path=relative, tree=tree, source=source))
        for func_node in _iter_all_function_defs(tree):
            project.index_function(FunctionDef(node=func_node, file_path=relative))
    return project
