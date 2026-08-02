"""Prometheus metrics for the runtime guardrail proxy.

Each `ProxyMetrics` instance owns its own `CollectorRegistry` rather than
using the library's global default registry -- this lets tests (and
multiple proxy instances in one process) construct independent metric sets
without hitting prometheus_client's "duplicate timeseries" registration
error.
"""
from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

from proxy.decision import PolicyDecision


class ProxyMetrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()

        self.tool_calls_total = Counter(
            "mcp_sentinel_proxy_tool_calls_total",
            "Total tool calls handled by the proxy",
            ["tool", "allowed"],
            registry=self.registry,
        )
        self.policy_denials_total = Counter(
            "mcp_sentinel_proxy_policy_denials_total",
            "Total tool calls denied by policy",
            ["tool", "rule_id"],
            registry=self.registry,
        )
        self.injection_attempts_total = Counter(
            "mcp_sentinel_proxy_injection_attempts_total",
            "Total tool outputs flagged by the injection detector",
            ["tool"],
            registry=self.registry,
        )
        self.tool_call_latency_seconds = Histogram(
            "mcp_sentinel_proxy_tool_call_latency_seconds",
            "Tool call latency as observed by the proxy",
            ["tool"],
            registry=self.registry,
        )

    def record_call(self, *, tool_name: str, decision: PolicyDecision, latency_seconds: float) -> None:
        self.tool_calls_total.labels(tool=tool_name, allowed=str(decision.allowed)).inc()
        self.tool_call_latency_seconds.labels(tool=tool_name).observe(latency_seconds)
        if not decision.allowed:
            self.policy_denials_total.labels(tool=tool_name, rule_id=decision.rule_id or "none").inc()

    def record_injection_attempt(self, *, tool_name: str) -> None:
        self.injection_attempts_total.labels(tool=tool_name).inc()

    def render(self) -> str:
        return generate_latest(self.registry).decode("utf-8")
