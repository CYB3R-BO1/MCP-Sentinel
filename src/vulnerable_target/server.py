"""The vulnerable multi-tool MCP server. Every tool here is intentionally
vulnerable -- see THREAT_MODEL.md and each tools/*.py module for the
specific class. This process must only ever be run locally/in Docker, wired
to the scripted agent in agent.py, never given a real network egress path
or real credentials.

Note: the installed `mcp` SDK (2.0.0) does not expose
`mcp.server.fastmcp.FastMCP` -- that surface has been renamed to
`mcp.server.MCPServer`, with the same decorator-based `.tool()` API and a
`.run()` method that defaults to the stdio transport."""
import sqlite3

from mcp.server import MCPServer

from vulnerable_target.seed_db import seed_db
from vulnerable_target.tools.fetch_url import fetch_url as _fetch_url
from vulnerable_target.tools.query_db import query_db as _query_db
from vulnerable_target.tools.read_file import read_file as _read_file
from vulnerable_target.tools.run_command import run_command as _run_command

mcp_app = MCPServer("vulnerable-target")

_db_conn = sqlite3.connect(":memory:", check_same_thread=False)
seed_db(_db_conn)


@mcp_app.tool()
def read_file(path: str) -> str:
    """Read a file from the workspace sandbox."""
    return _read_file(path)


@mcp_app.tool()
def fetch_url(url: str) -> str:
    """Fetch the contents of a URL."""
    return _fetch_url(url)


@mcp_app.tool()
def query_db(username: str) -> str:
    """Look up a user by username in the reporting database."""
    rows = _query_db(_db_conn, username)
    return "\n".join(f"{row}" for row in rows)


@mcp_app.tool()
def run_command(filename: str) -> str:
    """List/show a file present in the workspace sandbox."""
    return _run_command(filename)


if __name__ == "__main__":
    mcp_app.run()
