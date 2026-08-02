"""VULNERABLE ON PURPOSE: read_file does not normalize or contain `path`
within SANDBOX_ROOT, so a caller-supplied '../' escapes the sandbox
(THREAT_MODEL.md class #5, path traversal). This is a fixture for MCP
Sentinel's scanner and proxy, never call this against real data."""
from vulnerable_target.permissions import SANDBOX_ROOT


def read_file(path: str) -> str:
    target = SANDBOX_ROOT / path
    return target.read_text()
