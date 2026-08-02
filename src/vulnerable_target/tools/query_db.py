"""VULNERABLE ON PURPOSE: username is spliced into the SQL string with an
f-string instead of a parameterized query, so it is trivially SQL-
injectable (THREAT_MODEL.md class #6). This is a fixture for MCP
Sentinel's scanner and proxy, never call this against real data."""
import sqlite3


def query_db(conn: sqlite3.Connection, username: str) -> list[tuple]:
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor = conn.execute(query)
    return cursor.fetchall()
