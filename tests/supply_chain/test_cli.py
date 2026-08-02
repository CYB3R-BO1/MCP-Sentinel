import json

from supply_chain.cli import main


def test_terminal_format_prints_report_and_exits_zero(capsys):
    exit_code = main(["--skip-vuln-scan", "--format", "terminal"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "MCP Sentinel" in captured.out
    assert "SBOM:" in captured.out


def test_json_format_is_valid_json_on_stdout(capsys):
    exit_code = main(["--skip-vuln-scan", "--format", "json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["dependency_audit"] is None
    assert payload["sbom"]["bomFormat"] == "CycloneDX"


def test_output_file_is_written_instead_of_stdout(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    exit_code = main(["--skip-vuln-scan", "--format", "json", "--output", str(out_file)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["sbom"]["bomFormat"] == "CycloneDX"


def test_missing_requirements_file_exits_2(capsys):
    exit_code = main(["--requirements", "/definitely/not/a/real/file.txt"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "is not a file" in captured.err


def test_fail_on_copyleft_returns_1_when_a_copyleft_package_is_installed(tmp_path, capsys, monkeypatch):
    fake_report = {
        "sbom": {"components": [], "metadata": {"component": {"name": "x"}}},
        "license_check": {
            "total_packages": 1,
            "permissive_count": 0,
            "copyleft_count": 1,
            "unknown_count": 0,
            "flagged": [{"name": "g", "version": "1", "license": "GPL", "category": "copyleft"}],
            "packages": [],
        },
        "dependency_audit": None,
    }
    monkeypatch.setattr("supply_chain.cli.generate_supply_chain_report", lambda **kwargs: fake_report)
    exit_code = main(["--fail-on-copyleft", "--format", "json"])
    assert exit_code == 1


def test_fail_on_vulnerabilities_returns_1_when_vulnerabilities_present(monkeypatch):
    fake_report = {
        "sbom": {"components": [], "metadata": {"component": {"name": "x"}}},
        "license_check": {
            "total_packages": 0,
            "permissive_count": 0,
            "copyleft_count": 0,
            "unknown_count": 0,
            "flagged": [],
            "packages": [],
        },
        "dependency_audit": {
            "total_dependencies_scanned": 1,
            "vulnerable_dependency_count": 1,
            "total_vulnerabilities": 1,
            "vulnerable_dependencies": [],
        },
    }
    monkeypatch.setattr("supply_chain.cli.generate_supply_chain_report", lambda **kwargs: fake_report)
    exit_code = main(["--fail-on-vulnerabilities", "--format", "json"])
    assert exit_code == 1
