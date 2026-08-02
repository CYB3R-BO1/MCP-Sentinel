from __future__ import annotations

from dataclasses import dataclass, field

from taxonomy import Severity


@dataclass(frozen=True)
class Finding:
    """One concrete result from a scanner rule.

    `taint_trace` holds a human-readable propagation chain (source ->
    intermediate steps -> sink) for taint-based findings; it is empty for
    structural findings (e.g. excessive permission scope) that don't have
    a data-flow path.
    """

    rule_id: str
    severity: Severity
    message: str
    file_path: str  # POSIX-style, relative to the scan root
    line: int
    column: int
    taint_trace: tuple[str, ...] = field(default_factory=tuple)

    def dedup_key(self) -> tuple[str, str, int, int]:
        return (self.rule_id, self.file_path, self.line, self.column)
