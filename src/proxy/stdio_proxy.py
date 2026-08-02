"""The runtime guardrail proxy as a real stdio MCP server process.

Deviation from the original design-doc sketch, logged here per the
project's "log unilateral decisions" convention: the doc originally
described a proxy that spawns the real `vulnerable_target/server.py` as a
child process and passes raw JSON-RPC frames through by hand. This module
instead re-registers the same four tools directly on its own `MCPServer`
and calls the real tool implementations (`vulnerable_target/tools/*.py`)
in-process through `ProxyEngine.handle_tool_call`. The result is identical
from the agent's point of view -- it is still a distinct stdio MCP server
process sitting between the agent and the tools, and enforcement/blocking
is real, not simulated -- but it avoids hand-rolling MCP's JSON-RPC framing
a second time, which would duplicate the SDK's own client/server code for
no behavioral benefit at this project's scale.

A blocked call raises `ToolBlockedError`, which the underlying MCP SDK
converts into an `isError=True` tool result -- the agent sees a real tool
failure, not a silently empty response.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from mcp.server import MCPServer

from proxy.audit_log import AuditLogger
from proxy.interceptor import ProxyEngine
from proxy.metrics import ProxyMetrics
from proxy.policy import load_policy_fail_closed
from vulnerable_target.seed_db import seed_db
from vulnerable_target.tools.fetch_url import fetch_url as _fetch_url
from vulnerable_target.tools.query_db import query_db as _query_db
from vulnerable_target.tools.read_file import read_file as _read_file
from vulnerable_target.tools.run_command import run_command as _run_command

DEFAULT_POLICY_PATH = Path(__file__).parent / "default_policy.yaml"


class ToolBlockedError(RuntimeError):
    pass


def build_engine(policy_path: Path, audit_log_path: Path) -> tuple[ProxyEngine, list[str]]:
    policy, warnings = load_policy_fail_closed(policy_path)

    db_conn = sqlite3.connect(":memory:", check_same_thread=False)
    seed_db(db_conn)

    def _query_db_str(username: str) -> str:
        rows = _query_db(db_conn, username)
        return "\n".join(f"{row}" for row in rows)

    executors = {
        "read_file": _read_file,
        "fetch_url": _fetch_url,
        "query_db": _query_db_str,
        "run_command": _run_command,
    }

    engine = ProxyEngine(
        policy=policy,
        tool_executors=executors,
        audit_logger=AuditLogger(path=audit_log_path),
        metrics=ProxyMetrics(),
    )
    return engine, warnings


def build_app(engine: ProxyEngine) -> MCPServer:
    mcp_app = MCPServer("mcp-sentinel-proxy")

    def _call(tool_name: str, **arguments: str) -> str:
        result = engine.handle_tool_call(tool_name, arguments)
        if result.output is None:
            raise ToolBlockedError(f"blocked by mcp-sentinel-proxy: {result.decision.reason}")
        return result.output

    @mcp_app.tool()
    def read_file(path: str) -> str:
        """Read a file from the workspace sandbox."""
        return _call("read_file", path=path)

    @mcp_app.tool()
    def fetch_url(url: str) -> str:
        """Fetch the contents of a URL."""
        return _call("fetch_url", url=url)

    @mcp_app.tool()
    def query_db(username: str) -> str:
        """Look up a user by username in the reporting database."""
        return _call("query_db", username=username)

    @mcp_app.tool()
    def run_command(filename: str) -> str:
        """List/show a file present in the workspace sandbox."""
        return _call("run_command", filename=filename)

    return mcp_app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mcp-sentinel-proxy")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--audit-log", type=Path, default=Path("proxy-audit.jsonl"))
    args = parser.parse_args(argv)

    engine, warnings = build_engine(args.policy, args.audit_log)
    for warning in warnings:
        print(f"mcp-sentinel-proxy: policy warning (failing closed): {warning}", file=sys.stderr)

    app = build_app(engine)
    app.run()


if __name__ == "__main__":
    main()
