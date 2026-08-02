"""Heuristic detection of prompt-injection payloads embedded in tool output.

`vulnerable_target/agent.py` demonstrates the vulnerability this defends
against: a naive agent that treats any 'SYSTEM:'-prefixed text found in a
tool result as a real instruction. This module generalizes that one
hardcoded pattern into a small set of heuristics for the runtime proxy to
apply to every tool result *before* it is handed back to the agent -- this
is what makes THREAT_MODEL.md classes #3 and #4 (MCP-SENT-008/009), which
are explicitly "not statically detectable", detectable at runtime instead.

These are heuristics, not a classifier: false negatives (a cleverly worded
injection that avoids all patterns) are expected and out of scope for this
project's ambitions; false positives are logged as findings, not silently
dropped, so a human can review borderline output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_RULE_ID = "MCP-SENT-008"

_INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "system_directive": re.compile(r"\bsystem\s*:", re.IGNORECASE),
    "ignore_previous_instructions": re.compile(
        r"\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|earlier)\b.{0,20}\binstructions?\b",
        re.IGNORECASE,
    ),
    "role_override": re.compile(
        r"\b(new instructions|you are now|act as|developer mode|no restrictions)\b", re.IGNORECASE
    ),
    "instruction_heading": re.compile(r"^#{1,6}\s*(new )?instructions?\s*:", re.IGNORECASE | re.MULTILINE),
}


@dataclass(frozen=True)
class InjectionScanResult:
    flagged: bool
    matched_patterns: list[str] = field(default_factory=list)
    rule_id: str | None = None


def scan_for_injection(text: str) -> InjectionScanResult:
    matched = [name for name, pattern in _INJECTION_PATTERNS.items() if pattern.search(text)]
    if not matched:
        return InjectionScanResult(flagged=False)
    return InjectionScanResult(flagged=True, matched_patterns=matched, rule_id=_RULE_ID)
