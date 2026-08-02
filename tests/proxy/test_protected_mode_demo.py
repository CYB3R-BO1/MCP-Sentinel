"""The before/after demo: THREAT_MODEL.md's flagship prompt-injection-to-
exfiltration attack tree, re-run unprotected (against vulnerable_target's
raw server, in tests/vulnerable_target/test_agent_scenarios.py) and
protected (here, against mcp-sentinel-proxy). Same scenario, same scripted
agent, only the server process behind it differs -- proving the proxy
breaks the chain for real, not narrated."""
import sys
from pathlib import Path

import pytest

from vulnerable_target.agent import run_scenario
from vulnerable_target.mock_http_server import start_mock_server
from vulnerable_target.permissions import SECRET_PATH
from vulnerable_target.scenarios.prompt_injection_chaining import PROMPT_INJECTION_CHAINING_SCENARIO

_DEFAULT_POLICY = Path(__file__).parent.parent.parent / "src" / "proxy" / "default_policy.yaml"


@pytest.fixture
def mock_server():
    handle = start_mock_server()
    yield handle
    handle.stop()


@pytest.mark.asyncio
async def test_protected_mode_blocks_the_exfiltration_chain(mock_server, tmp_path):
    transcript = await run_scenario(
        PROMPT_INJECTION_CHAINING_SCENARIO,
        mock_server.port,
        command=sys.executable,
        args=[
            "-m",
            "proxy.stdio_proxy",
            "--policy",
            str(_DEFAULT_POLICY),
            "--audit-log",
            str(tmp_path / "audit.jsonl"),
        ],
    )

    # The chain breaks one step earlier than the naive-agent trigger point:
    # the injection detector flags fetch_url's own output (it contains the
    # embedded "SYSTEM:" directive) and blocks it before returning it to
    # the agent, so the agent never even sees the instruction that would
    # have triggered the unintended read_file follow-up call. This is
    # THREAT_MODEL.md class #4 (MCP-SENT-009, insecure output handling)
    # breaking the chain before class #3 (MCP-SENT-008) has a chance to.
    tool_names = [name for name, _ in transcript.tool_calls]
    assert tool_names == ["fetch_url"]

    # The secret itself never reaches the agent's final context.
    assert "FIXTURE-SECRET" not in transcript.final_output
    assert SECRET_PATH.read_text().strip() not in transcript.final_output
    assert "blocked by mcp-sentinel-proxy" in transcript.final_output
