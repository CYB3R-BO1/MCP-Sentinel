import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_server_exposes_all_four_tools():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "vulnerable_target.server"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            names = {tool.name for tool in result.tools}
            assert names == {"read_file", "fetch_url", "query_db", "run_command"}


@pytest.mark.asyncio
async def test_server_read_file_tool_call_round_trips():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "vulnerable_target.server"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "README.txt"})
            text = "".join(block.text for block in result.content if hasattr(block, "text"))
            assert "sandbox root" in text
