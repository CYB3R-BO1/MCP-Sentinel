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

    def snapshot(self) -> dict:
        """Aggregate counters/histograms into plain dicts for the
        /dashboard HTML view: total calls, denials and injection attempts
        per tool, SSRF-specific denial count, and average latency per
        tool. Walks the same CollectorRegistry `render()` reads from, so
        the dashboard and the Prometheus endpoint never disagree."""
        calls_by_tool: dict[str, int] = {}
        denials_by_tool: dict[str, int] = {}
        ssrf_attempts = 0
        injection_attempts_by_tool: dict[str, int] = {}
        latency_sum_by_tool: dict[str, float] = {}
        latency_count_by_tool: dict[str, int] = {}

        for family in self.registry.collect():
            if family.name == "mcp_sentinel_proxy_tool_calls":
                for sample in family.samples:
                    if sample.name.endswith("_total"):
                        tool = sample.labels["tool"]
                        calls_by_tool[tool] = calls_by_tool.get(tool, 0) + int(sample.value)
            elif family.name == "mcp_sentinel_proxy_policy_denials":
                for sample in family.samples:
                    if sample.name.endswith("_total"):
                        tool = sample.labels["tool"]
                        denials_by_tool[tool] = denials_by_tool.get(tool, 0) + int(sample.value)
                        if sample.labels.get("rule_id") == "MCP-SENT-002":
                            ssrf_attempts += int(sample.value)
            elif family.name == "mcp_sentinel_proxy_injection_attempts":
                for sample in family.samples:
                    if sample.name.endswith("_total"):
                        tool = sample.labels["tool"]
                        injection_attempts_by_tool[tool] = injection_attempts_by_tool.get(tool, 0) + int(
                            sample.value
                        )
            elif family.name == "mcp_sentinel_proxy_tool_call_latency_seconds":
                for sample in family.samples:
                    tool = sample.labels.get("tool")
                    if tool is None:
                        continue
                    if sample.name.endswith("_sum"):
                        latency_sum_by_tool[tool] = latency_sum_by_tool.get(tool, 0.0) + sample.value
                    elif sample.name.endswith("_count"):
                        latency_count_by_tool[tool] = latency_count_by_tool.get(tool, 0) + int(sample.value)

        avg_latency_by_tool = {
            tool: latency_sum_by_tool[tool] / count for tool, count in latency_count_by_tool.items() if count > 0
        }
        most_abused_tool = max(denials_by_tool, key=denials_by_tool.get) if denials_by_tool else None

        return {
            "total_calls": sum(calls_by_tool.values()),
            "calls_by_tool": calls_by_tool,
            "denials_by_tool": denials_by_tool,
            "most_abused_tool": most_abused_tool,
            "ssrf_attempts": ssrf_attempts,
            "injection_attempts_by_tool": injection_attempts_by_tool,
            "avg_latency_by_tool": avg_latency_by_tool,
        }
