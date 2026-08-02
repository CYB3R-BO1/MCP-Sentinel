"""VULNERABLE ON PURPOSE: filename is interpolated into a shell=True
command string instead of passed as an argv list, so shell metacharacters
like ';' let an attacker chain arbitrary commands (THREAT_MODEL.md class
#7). Declared purpose is narrowly 'list files' but the actual capability
is arbitrary shell execution -- also the concrete example behind class #1
(overly broad permission scope vs. declared purpose). This is a fixture
for MCP Sentinel's scanner and proxy, never call this against real data."""
import subprocess

from vulnerable_target.permissions import SANDBOX_ROOT


def run_command(filename: str) -> str:
    result = subprocess.run(
        f"cat {filename}",
        shell=True,
        capture_output=True,
        text=True,
        cwd=SANDBOX_ROOT,
    )
    return result.stdout + result.stderr
