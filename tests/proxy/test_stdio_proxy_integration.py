"""Integration tests that spawn the real proxy stdio MCP server process
(not mocked) and drive it with a real MCP ClientSession, mirroring
tests/vulnerable_target/test_agent_scenarios.py's pattern. These prove
attacks are actually blocked by a running process, not narrated."""
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from vulnerable_target.mock_http_server import start_mock_server

_DEFAULT_POLICY = Path(__file__).parent.parent.parent / "src" / "proxy" / "default_policy.yaml"


@pytest.fixture
def mock_server():
    handle = start_mock_server()
    yield handle
    handle.stop()


def _params(policy_path: Path, audit_log_path: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "proxy.stdio_proxy",
            "--policy",
            str(policy_path),
            "--audit-log",
            str(audit_log_path),
        ],
    )


def _extract_text(result) -> str:
    return "".join(block.text for block in result.content if hasattr(block, "text"))


@pytest.mark.asyncio
async def test_allowed_fetch_call_returns_real_content(mock_server, tmp_path):
    async with stdio_client(_params(_DEFAULT_POLICY, tmp_path / "audit.jsonl")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("fetch_url", {"url": f"http://127.0.0.1:{mock_server.port}/internal/admin"})

    assert result.is_error is not True
    assert "INTERNAL-FIXTURE-SECRET" in _extract_text(result)


@pytest.mark.asyncio
async def test_disallowed_host_is_blocked_for_real(mock_server, tmp_path):
    async with stdio_client(_params(_DEFAULT_POLICY, tmp_path / "audit.jsonl")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"})

    assert result.is_error is True


@pytest.mark.asyncio
async def test_path_traversal_read_is_blocked_for_real(mock_server, tmp_path):
    async with stdio_client(_params(_DEFAULT_POLICY, tmp_path / "audit.jsonl")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "../secret.txt"})

    assert result.is_error is True


@pytest.mark.asyncio
async def test_run_command_disabled_by_default_policy(mock_server, tmp_path):
    async with stdio_client(_params(_DEFAULT_POLICY, tmp_path / "audit.jsonl")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("run_command", {"filename": "a.txt"})

    assert result.is_error is True


@pytest.mark.asyncio
async def test_sql_injection_looking_username_is_blocked(mock_server, tmp_path):
    async with stdio_client(_params(_DEFAULT_POLICY, tmp_path / "audit.jsonl")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("query_db", {"username": "' OR '1'='1"})

    assert result.is_error is True


@pytest.mark.asyncio
async def test_audit_log_is_written_by_the_real_process(mock_server, tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    async with stdio_client(_params(_DEFAULT_POLICY, audit_log)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("fetch_url", {"url": f"http://127.0.0.1:{mock_server.port}/internal/admin"})

    assert audit_log.exists()
    assert len(audit_log.read_text(encoding="utf-8").strip().splitlines()) == 1


@pytest.mark.asyncio
async def test_missing_policy_file_fails_closed_and_blocks_everything(mock_server, tmp_path):
    async with stdio_client(_params(tmp_path / "does-not-exist.yaml", tmp_path / "audit.jsonl")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("fetch_url", {"url": f"http://127.0.0.1:{mock_server.port}/internal/admin"})

    assert result.is_error is True
