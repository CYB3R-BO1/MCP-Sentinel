import json

import pytest

from scanner.cli import main

VULNERABLE_TARGET = "src/vulnerable_target"


def test_terminal_format_prints_report_and_exits_zero_without_fail_on(capsys):
    exit_code = main([VULNERABLE_TARGET, "--format", "terminal"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "MCP Sentinel" in captured.out
    assert "MCP-SENT-005" in captured.out


def test_json_format_is_valid_json_on_stdout(capsys):
    exit_code = main([VULNERABLE_TARGET, "--format", "json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["summary"]["total"] >= 6


def test_sarif_format_is_valid_json_with_sarif_version(capsys):
    exit_code = main([VULNERABLE_TARGET, "--format", "sarif"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["version"] == "2.1.0"


def test_fail_on_critical_returns_1_because_vulnerable_target_has_critical_findings(capsys):
    exit_code = main([VULNERABLE_TARGET, "--format", "json", "--fail-on", "critical"])
    assert exit_code == 1


def test_fail_on_a_severity_with_no_matching_findings_returns_0(capsys, monkeypatch, tmp_path):
    (tmp_path / "clean.py").write_text("def helper(x):\n    return x + 1\n", encoding="utf-8")
    exit_code = main([str(tmp_path), "--format", "json", "--fail-on", "low"])
    assert exit_code == 0


def test_output_file_is_written_instead_of_stdout(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    exit_code = main([VULNERABLE_TARGET, "--format", "json", "--output", str(out_file)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] >= 6


def test_nonexistent_path_exits_2(capsys):
    exit_code = main(["/definitely/does/not/exist/anywhere"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "not a directory" in captured.err


def test_invalid_format_choice_raises_systemexit():
    with pytest.raises(SystemExit):
        main([VULNERABLE_TARGET, "--format", "yaml"])
