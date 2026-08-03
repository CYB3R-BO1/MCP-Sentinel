from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Ordered low -> critical. Values are used directly in JSON/SARIF
    output and in --fail-on comparisons, so do not rename them lightly."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


@dataclass(frozen=True)
class TaxonomyEntry:
    """One row of THREAT_MODEL.md's STRIDE table, in machine-readable form."""

    rule_id: str
    title: str
    stride: tuple[str, ...]
    owasp_top_10: str | None
    owasp_llm_top_10: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    default_severity: Severity
    threat_model_class: int
