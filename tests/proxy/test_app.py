from fastapi.testclient import TestClient

from proxy.app import create_app
from proxy.decision import allow, deny
from proxy.metrics import ProxyMetrics


def test_metrics_endpoint_returns_prometheus_text():
    metrics = ProxyMetrics()
    metrics.record_call(
        tool_name="read_file", decision=allow(tool_name="read_file", correlation_id="c1", reason="ok"),
        latency_seconds=0.01,
    )
    client = TestClient(create_app(metrics))

    response = client.get("/metrics")

    assert response.status_code == 200
    assert "mcp_sentinel_proxy_tool_calls_total" in response.text
    assert response.headers["content-type"].startswith("text/plain")


def test_dashboard_endpoint_returns_html():
    metrics = ProxyMetrics()
    client = TestClient(create_app(metrics))

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "MCP Sentinel" in response.text


def test_dashboard_shows_most_abused_tool_and_ssrf_count():
    metrics = ProxyMetrics()
    metrics.record_call(
        tool_name="fetch_url",
        decision=deny(tool_name="fetch_url", correlation_id="c1", reason="ssrf", rule_id="MCP-SENT-002"),
        latency_seconds=0.01,
    )
    client = TestClient(create_app(metrics))

    response = client.get("/dashboard")

    assert "fetch_url" in response.text
    assert "SSRF" in response.text


def test_dashboard_escapes_html_in_tool_names():
    """Regression: tool names are Prometheus label values sourced from
    ProxyEngine.handle_tool_call's tool_name argument -- untrusted in a
    general MCP deployment -- and were being interpolated into the
    dashboard's HTML unescaped."""
    metrics = ProxyMetrics()
    metrics.record_call(
        tool_name="<script>alert(1)</script>",
        decision=allow(tool_name="<script>alert(1)</script>", correlation_id="c1", reason="ok"),
        latency_seconds=0.01,
    )
    client = TestClient(create_app(metrics))

    response = client.get("/dashboard")

    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_root_redirects_to_dashboard():
    metrics = ProxyMetrics()
    client = TestClient(create_app(metrics))

    response = client.get("/", follow_redirects=False)

    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/dashboard"
