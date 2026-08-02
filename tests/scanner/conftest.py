import pytest

from scanner.findings import Finding
from scanner.project import load_project
from scanner.rules import DEFAULT_SINK_RULES
from scanner.taint.engine import analyze_project


@pytest.fixture
def scan_source(tmp_path):
    """Write `code` to a single-file scan root and return the findings the
    default sink rules produce against it."""

    def _scan(code: str, filename: str = "mod.py") -> list[Finding]:
        (tmp_path / filename).write_text(code, encoding="utf-8")
        project = load_project(tmp_path)
        return analyze_project(project, DEFAULT_SINK_RULES)

    return _scan
