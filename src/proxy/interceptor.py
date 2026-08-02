"""The proxy's core enforcement engine: one call to `handle_tool_call` is
the single choke point every tool invocation passes through, in this order:

  1. resolve the tool's policy (enabled? rate limit? containment rules?)
  2. rate-limit check
  3. tool-argument containment check (host allowlist / path allowlist /
     readonly-SQL heuristic) -- generic over argument names so it applies
     to any MCP server's tools, not just vulnerable_target's four
  4. if still allowed (or policy.dry_run), execute the real tool
  5. scan the tool's output for embedded prompt-injection content and
     fold that into the decision if it flags and blocking is configured
  6. audit-log and metrics-record the final decision either way

`policy.dry_run` never withholds a tool's real output or execution -- it
only prevents step 2/3/5 denials from suppressing the result, so the
proxy can run in "report only" mode against production-shaped traffic
before anyone trusts it to actually block.
"""
from __future__ import annotations

import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from proxy.audit_log import AuditLogger
from proxy.decision import PolicyDecision, allow, deny
from proxy.injection_detector import InjectionScanResult, scan_for_injection
from proxy.metrics import ProxyMetrics
from proxy.policy import Policy, ToolPolicy, resolve_tool_policy
from proxy.rate_limiter import SlidingWindowRateLimiter

_SQL_WRITE_OR_INJECTION_RE = re.compile(
    r"(--|;|\bunion\b|\bdrop\b|\binsert\b|\bupdate\b|\bdelete\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ToolCallResult:
    correlation_id: str
    tool_name: str
    output: str | None
    decision: PolicyDecision
    injection_result: InjectionScanResult | None
    latency_seconds: float


def _check_containment(tool_policy: ToolPolicy, arguments: dict[str, Any]) -> tuple[bool, str, str | None]:
    if tool_policy.allow_hosts is not None:
        for value in arguments.values():
            if isinstance(value, str) and "://" in value:
                host = urlparse(value).hostname
                if host not in tool_policy.allow_hosts:
                    return False, f"host {host!r} is not in the allowed hosts list", "MCP-SENT-002"

    if tool_policy.allow_path_prefixes is not None:
        for value in arguments.values():
            if not isinstance(value, str):
                continue
            normalized = value.replace("\\", "/")
            if ".." in normalized.split("/"):
                return False, f"path {value!r} contains a '..' traversal segment", "MCP-SENT-003"
            if not any(normalized.startswith(prefix) for prefix in tool_policy.allow_path_prefixes):
                return False, f"path {value!r} is outside the allowed path prefixes", "MCP-SENT-003"

    if tool_policy.readonly:
        for value in arguments.values():
            if isinstance(value, str) and _SQL_WRITE_OR_INJECTION_RE.search(value):
                return False, f"argument {value!r} looks like a SQL write/injection attempt", "MCP-SENT-004"

    return True, "", None


class ProxyEngine:
    def __init__(
        self,
        *,
        policy: Policy,
        tool_executors: dict[str, Callable[..., str]],
        audit_logger: AuditLogger,
        metrics: ProxyMetrics,
        rate_limiter: SlidingWindowRateLimiter | None = None,
        clock: Callable[[], float] = time.monotonic,
        id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
    ):
        self.policy = policy
        self._tool_executors = tool_executors
        self._audit_logger = audit_logger
        self._metrics = metrics
        self._rate_limiter = rate_limiter or SlidingWindowRateLimiter(clock=clock)
        self._clock = clock
        self._id_factory = id_factory

    def handle_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> ToolCallResult:
        start = self._clock()
        correlation_id = self._id_factory()
        tool_policy = resolve_tool_policy(self.policy, tool_name)

        decision = self._evaluate_access(tool_name, correlation_id, tool_policy, arguments)

        output: str | None = None
        injection_result: InjectionScanResult | None = None

        if decision.allowed or self.policy.dry_run:
            output = self._tool_executors[tool_name](**arguments)
            if self.policy.injection_detection.enabled:
                injection_result = scan_for_injection(output)
                if injection_result.flagged:
                    self._metrics.record_injection_attempt(tool_name=tool_name)
                    if (
                        decision.allowed
                        and self.policy.injection_detection.block_on_detection
                        and not self.policy.dry_run
                    ):
                        decision = deny(
                            tool_name=tool_name,
                            correlation_id=correlation_id,
                            reason=f"tool output flagged by injection detector: {injection_result.matched_patterns}",
                            rule_id=injection_result.rule_id,
                        )

        final_output = output if (decision.allowed or self.policy.dry_run) else None
        latency_seconds = self._clock() - start

        self._audit_logger.log_call(
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
            latency_seconds=latency_seconds,
            injection_result=injection_result,
        )
        self._metrics.record_call(tool_name=tool_name, decision=decision, latency_seconds=latency_seconds)

        return ToolCallResult(
            correlation_id=correlation_id,
            tool_name=tool_name,
            output=final_output,
            decision=decision,
            injection_result=injection_result,
            latency_seconds=latency_seconds,
        )

    def _evaluate_access(
        self, tool_name: str, correlation_id: str, tool_policy: ToolPolicy, arguments: dict[str, Any]
    ) -> PolicyDecision:
        if not tool_policy.enabled:
            return deny(
                tool_name=tool_name,
                correlation_id=correlation_id,
                reason="tool disabled by policy",
                dry_run=self.policy.dry_run,
            )

        max_calls = tool_policy.max_calls_per_minute or self.policy.max_calls_per_minute
        if not self._rate_limiter.allow(tool_name, max_calls=max_calls, window_seconds=60.0):
            return deny(
                tool_name=tool_name,
                correlation_id=correlation_id,
                reason=f"rate limit exceeded ({max_calls} calls/minute)",
                rule_id="MCP-SENT-006",
                dry_run=self.policy.dry_run,
            )

        ok, reason, rule_id = _check_containment(tool_policy, arguments)
        if not ok:
            return deny(
                tool_name=tool_name,
                correlation_id=correlation_id,
                reason=reason,
                rule_id=rule_id,
                dry_run=self.policy.dry_run,
            )

        return allow(tool_name=tool_name, correlation_id=correlation_id, reason="policy permits this call")
