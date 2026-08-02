from proxy.decision import allow, deny
from proxy.metrics import ProxyMetrics


def test_record_call_increments_total_and_latency():
    metrics = ProxyMetrics()
    decision = allow(tool_name="read_file", correlation_id="c1", reason="ok")
    metrics.record_call(tool_name="read_file", decision=decision, latency_seconds=0.05)

    rendered = metrics.render()
    assert "mcp_sentinel_proxy_tool_calls_total" in rendered
    assert "mcp_sentinel_proxy_tool_call_latency_seconds" in rendered


def test_record_call_increments_denials_when_blocked():
    metrics = ProxyMetrics()
    decision = deny(tool_name="run_command", correlation_id="c2", reason="disabled", rule_id="MCP-SENT-001")
    metrics.record_call(tool_name="run_command", decision=decision, latency_seconds=0.01)

    rendered = metrics.render()
    assert "mcp_sentinel_proxy_policy_denials_total" in rendered
    assert 'tool="run_command"' in rendered


def test_record_injection_attempt_increments_counter():
    metrics = ProxyMetrics()
    metrics.record_injection_attempt(tool_name="fetch_url")

    rendered = metrics.render()
    assert "mcp_sentinel_proxy_injection_attempts_total" in rendered
    assert 'tool="fetch_url"' in rendered


def test_render_is_valid_prometheus_text_format():
    metrics = ProxyMetrics()
    metrics.record_call(
        tool_name="read_file",
        decision=allow(tool_name="read_file", correlation_id="c1", reason="ok"),
        latency_seconds=0.02,
    )
    rendered = metrics.render()
    assert rendered.strip() != ""
    assert isinstance(rendered, str)
