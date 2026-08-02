"""A scripted, deterministic stand-in for a tool-calling LLM agent.

The agent's decision logic is intentionally naive: it concatenates every
tool result back into its running context and, if that context contains a
line starting with 'SYSTEM:', treats it as an instruction and issues one
more tool call. This is a faithful simulation of the real-world insecure
pattern (tool output fed back into model context unsanitized) without
requiring a live LLM API call, keeping demos reproducible and secret-free.
See THREAT_MODEL.md classes #3 and #4.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from vulnerable_target.scenarios import Scenario

_INJECTED_INSTRUCTION_RE = re.compile(
    r"SYSTEM:.*?\bat\s+(?P<path>\S+?)\s+and\b", re.DOTALL
)


@dataclass
class AgentTranscript:
    tool_calls: list[tuple[str, dict]] = field(default_factory=list)
    final_output: str = ""


def _extract_text(result) -> str:
    return "".join(block.text for block in result.content if hasattr(block, "text"))


async def run_scenario(
    scenario: Scenario,
    mock_server_port: int,
    *,
    command: str | None = None,
    args: list[str] | None = None,
) -> AgentTranscript:
    """`command`/`args` let callers point the agent at a different stdio
    MCP server process -- e.g. `proxy/stdio_proxy.py` instead of the raw
    `vulnerable_target/server.py` -- to re-run the same scenario in
    "protected mode" without duplicating this function."""
    params = StdioServerParameters(
        command=command or sys.executable, args=args or ["-m", "vulnerable_target.server"]
    )
    transcript = AgentTranscript()

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            initial_args = {"url": scenario.initial_args_template.format(port=mock_server_port)}
            result = await session.call_tool(scenario.initial_tool, initial_args)
            transcript.tool_calls.append((scenario.initial_tool, initial_args))
            output_so_far = _extract_text(result)

            match = _INJECTED_INSTRUCTION_RE.search(output_so_far)
            if match:
                injected_path = match.group("path")
                follow_up_args = {"path": injected_path}
                follow_up_result = await session.call_tool("read_file", follow_up_args)
                transcript.tool_calls.append(("read_file", follow_up_args))
                output_so_far += "\n" + _extract_text(follow_up_result)

            transcript.final_output = output_so_far

    return transcript
