"""Contract for a project-level (non-taint) rule. Unlike a `SinkRule`,
these don't participate in the taint engine's per-call dispatch -- they
look at whole-file or whole-project structure (a permission manifest's
shape, whether any rate-limiting construct appears anywhere in a file that
registers tool endpoints, whether a tool's docstring reads like a planted
instruction) and build their own `Finding` objects directly."""
from __future__ import annotations

from scanner.findings import Finding
from scanner.project import Project


class StructuralRule:
    rule_id: str

    def check_project(self, project: Project) -> list[Finding]:
        raise NotImplementedError
