"""Replay mode: re-evaluate a captured audit log against a (possibly
updated) policy without re-executing any tool, so a policy change can be
sanity-checked against real historical traffic before it's deployed.

Only the access-decision portion (enabled / rate limit / containment) is
replayed, using the exact same `evaluate_access` function the live
`ProxyEngine` calls -- not a second implementation that could drift. The
injection-detection step is not replayed: it depends on the tool's actual
output, which the audit log does not store.

Rate limiting is replayed using each record's *recorded* timestamp, in
order, rather than "all at once" -- so a `max_calls_per_minute` policy
change is evaluated against the real historical call cadence, not an
artificially compressed one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from proxy.interceptor import evaluate_access
from proxy.policy import Policy, resolve_tool_policy
from proxy.rate_limiter import SlidingWindowRateLimiter


@dataclass(frozen=True)
class ReplayResult:
    correlation_id: str
    tool_name: str
    arguments: dict[str, Any]
    original_allowed: bool
    original_reason: str
    replayed_allowed: bool
    replayed_reason: str

    @property
    def changed(self) -> bool:
        return self.original_allowed != self.replayed_allowed


class _ReplayClock:
    def __init__(self) -> None:
        self.now: float = 0.0

    def __call__(self) -> float:
        return self.now


def replay_audit_log(audit_log_path: Path, policy: Policy) -> list[ReplayResult]:
    lines = [line for line in audit_log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return []

    clock = _ReplayClock()
    rate_limiter = SlidingWindowRateLimiter(clock=clock)
    results: list[ReplayResult] = []

    for line in lines:
        record = json.loads(line)
        clock.now = datetime.fromisoformat(record["timestamp"]).timestamp()

        tool_name = record["tool_name"]
        arguments = record["arguments"]
        tool_policy = resolve_tool_policy(policy, tool_name)

        replayed_decision = evaluate_access(
            policy=policy,
            tool_policy=tool_policy,
            tool_name=tool_name,
            correlation_id=record["correlation_id"],
            arguments=arguments,
            rate_limiter=rate_limiter,
        )

        results.append(
            ReplayResult(
                correlation_id=record["correlation_id"],
                tool_name=tool_name,
                arguments=arguments,
                original_allowed=record["decision"]["allowed"],
                original_reason=record["decision"]["reason"],
                replayed_allowed=replayed_decision.allowed,
                replayed_reason=replayed_decision.reason,
            )
        )

    return results


def summarize_replay(results: list[ReplayResult]) -> dict[str, int]:
    changed = [r for r in results if r.changed]
    return {
        "total": len(results),
        "changed": len(changed),
        "newly_blocked": sum(1 for r in changed if r.original_allowed and not r.replayed_allowed),
        "newly_allowed": sum(1 for r in changed if not r.original_allowed and r.replayed_allowed),
    }
