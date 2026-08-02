"""The proxy's policy-decision record.

Every enforcement point in the proxy (rate limiter, tool policy check,
injection detector) produces one of these instead of a bare bool, so the
audit log and the agent-facing error can always explain *why* a call was
blocked -- "decision explanations" are a first-class part of the record,
not an afterthought bolted onto logging.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    tool_name: str
    correlation_id: str
    reason: str
    rule_id: str | None = None
    dry_run: bool = False


def allow(
    *, tool_name: str, correlation_id: str, reason: str, rule_id: str | None = None, dry_run: bool = False
) -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        tool_name=tool_name,
        correlation_id=correlation_id,
        reason=reason,
        rule_id=rule_id,
        dry_run=dry_run,
    )


def deny(
    *, tool_name: str, correlation_id: str, reason: str, rule_id: str | None = None, dry_run: bool = False
) -> PolicyDecision:
    return PolicyDecision(
        allowed=False,
        tool_name=tool_name,
        correlation_id=correlation_id,
        reason=reason,
        rule_id=rule_id,
        dry_run=dry_run,
    )
