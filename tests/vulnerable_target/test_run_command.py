import sys

import pytest

from vulnerable_target.tools.run_command import run_command


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="run_command's shell=True sink uses POSIX shell semantics (';' chaining, "
    "'cat'); this project targets Docker/Linux per "
    "docs/superpowers/specs/2026-08-02-mcp-sentinel-design.md — run this test suite "
    "in Docker or WSL for full coverage on Windows dev hosts",
)
def test_lists_a_real_file_in_the_sandbox():
    output = run_command("README.txt")
    assert "sandbox root" in output


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="run_command's shell=True sink uses POSIX shell semantics (';' chaining, "
    "'cat'); this project targets Docker/Linux per "
    "docs/superpowers/specs/2026-08-02-mcp-sentinel-design.md — run this test suite "
    "in Docker or WSL for full coverage on Windows dev hosts",
)
def test_shell_injection_via_command_chaining():
    """Proves the vulnerability: filename is interpolated into a shell=True
    command string, so ';'-chaining lets an attacker run an arbitrary
    second command instead of the intended single cat."""
    output = run_command("nonexistent.txt; echo INJECTED_MARKER")
    assert "INJECTED_MARKER" in output
