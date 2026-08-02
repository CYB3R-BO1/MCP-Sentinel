"""Declared tool permission scopes for vulnerable_target.

These scopes are intentionally broader than each tool's declared purpose
requires -- this mismatch is the "no least privilege" vulnerability class
(#1 in THREAT_MODEL.md) and is what the static scanner (sub-project 2)
flags by comparing `scopes` against `declared_purpose`.
"""
from pathlib import Path
from typing import TypedDict


class ToolPermission(TypedDict):
    scopes: list[str]
    declared_purpose: str


TOOL_PERMISSIONS: dict[str, ToolPermission] = {
    "read_file": {
        "scopes": ["fs:read:*"],
        "declared_purpose": "read files within the workspace sandbox",
    },
    "fetch_url": {
        "scopes": ["net:http:*"],
        "declared_purpose": "fetch a single, already-known reporting endpoint",
    },
    "query_db": {
        "scopes": ["db:read", "db:write"],
        "declared_purpose": "run read-only reporting queries against the users table",
    },
    "run_command": {
        "scopes": ["exec:*"],
        "declared_purpose": "list files present in the workspace sandbox",
    },
}

_SANDBOX_DIR = Path(__file__).parent / "sandbox"
SANDBOX_ROOT = _SANDBOX_DIR / "files"
SECRET_PATH = _SANDBOX_DIR / "secret.txt"
