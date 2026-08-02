"""FastAPI app exposing the proxy's Prometheus metrics and a minimal HTML
dashboard, both reading the same in-memory `ProxyMetrics` instance the
`ProxyEngine` records into -- there is no separate metrics store to fall
out of sync."""
from __future__ import annotations

import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST

from proxy.metrics import ProxyMetrics


def create_app(metrics: ProxyMetrics) -> FastAPI:
    app = FastAPI(title="MCP Sentinel Proxy")

    @app.get("/")
    def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard")

    @app.get("/metrics")
    def get_metrics() -> Response:
        return Response(content=metrics.render(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/dashboard", response_class=HTMLResponse)
    def get_dashboard() -> str:
        return _render_dashboard(metrics.snapshot())

    return app


def _render_dashboard(snapshot: dict) -> str:
    # Tool names are Prometheus label values sourced from
    # ProxyEngine.handle_tool_call's tool_name argument -- in a general MCP
    # deployment that can be influenced by whatever the connected client
    # requests, so they are untrusted input here and must be escaped before
    # being interpolated into HTML, same as any other reflected value.
    rows = "".join(
        f"<tr><td>{html.escape(tool)}</td><td>{snapshot['calls_by_tool'].get(tool, 0)}</td>"
        f"<td>{snapshot['denials_by_tool'].get(tool, 0)}</td>"
        f"<td>{snapshot['injection_attempts_by_tool'].get(tool, 0)}</td>"
        f"<td>{snapshot['avg_latency_by_tool'].get(tool, 0.0):.4f}s</td></tr>"
        for tool in sorted(snapshot["calls_by_tool"].keys() | snapshot["denials_by_tool"].keys())
    )
    most_abused = html.escape(snapshot["most_abused_tool"] or "none")
    return f"""
<html>
<head><title>MCP Sentinel Proxy Dashboard</title></head>
<body>
<h1>MCP Sentinel Proxy Dashboard</h1>
<ul>
  <li>Total tool calls: {snapshot['total_calls']}</li>
  <li>Most-abused tool (most policy denials): {most_abused}</li>
  <li>SSRF (MCP-SENT-002) attempts blocked: {snapshot['ssrf_attempts']}</li>
</ul>
<table border="1" cellpadding="4">
  <tr><th>Tool</th><th>Calls</th><th>Denials</th><th>Injection attempts</th><th>Avg latency</th></tr>
  {rows}
</table>
</body>
</html>
"""
