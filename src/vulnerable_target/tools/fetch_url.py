"""VULNERABLE ON PURPOSE: fetch_url has no host/path allowlist, so it will
fetch any URL it is given, including internal-only endpoints (SSRF,
THREAT_MODEL.md class #2). This is a fixture for MCP Sentinel's scanner
and proxy; it must only ever be pointed at the local mock HTTP server."""
import urllib.request


def fetch_url(url: str) -> str:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")
