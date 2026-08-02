"""Tests the pip-audit wrapper's summarization logic and CLI-invocation
plumbing without making a real network call: `summarize_pip_audit_payload`
is tested directly against a canned payload (this is the part with real
logic), and `run_dependency_audit` is tested with `subprocess.run`
monkeypatched so the test suite stays fast, deterministic, and offline."""
import json
from types import SimpleNamespace

import pytest

from supply_chain.vuln_scan import (
    PipAuditFailed,
    PipAuditNotAvailable,
    run_dependency_audit,
    summarize_pip_audit_payload,
)

_CANNED_PAYLOAD = {
    "dependencies": [
        {"name": "safe-pkg", "version": "1.0.0", "vulns": []},
        {
            "name": "vulnerable-pkg",
            "version": "2.0.0",
            "vulns": [
                {
                    "id": "PYSEC-2024-1",
                    "fix_versions": ["2.0.1"],
                    "aliases": ["CVE-2024-0001"],
                    "description": "A vulnerability.",
                },
                {
                    "id": "PYSEC-2024-2",
                    "fix_versions": [],
                    "aliases": [],
                    "description": "Another vulnerability.",
                },
            ],
        },
    ]
}


def test_summarize_counts_and_shape():
    summary = summarize_pip_audit_payload(_CANNED_PAYLOAD)
    assert summary["total_dependencies_scanned"] == 2
    assert summary["vulnerable_dependency_count"] == 1
    assert summary["total_vulnerabilities"] == 2
    assert len(summary["vulnerable_dependencies"]) == 1
    dep = summary["vulnerable_dependencies"][0]
    assert dep["name"] == "vulnerable-pkg"
    assert {v["id"] for v in dep["vulnerabilities"]} == {"PYSEC-2024-1", "PYSEC-2024-2"}


def test_summarize_empty_dependencies():
    summary = summarize_pip_audit_payload({"dependencies": []})
    assert summary["total_dependencies_scanned"] == 0
    assert summary["vulnerable_dependency_count"] == 0
    assert summary["total_vulnerabilities"] == 0
    assert summary["vulnerable_dependencies"] == []


def test_run_dependency_audit_raises_when_pip_audit_not_on_path(monkeypatch):
    monkeypatch.setattr("supply_chain.vuln_scan.shutil.which", lambda name: None)
    with pytest.raises(PipAuditNotAvailable):
        run_dependency_audit()


def test_run_dependency_audit_parses_json_from_subprocess(monkeypatch):
    monkeypatch.setattr("supply_chain.vuln_scan.shutil.which", lambda name: "/usr/bin/pip-audit")

    def fake_run(args, capture_output, text, timeout):
        assert "--local" in args
        assert "--format" in args and "json" in args
        return SimpleNamespace(returncode=1, stdout=json.dumps(_CANNED_PAYLOAD), stderr="")

    monkeypatch.setattr("supply_chain.vuln_scan.subprocess.run", fake_run)
    summary = run_dependency_audit()
    assert summary["total_vulnerabilities"] == 2


def test_run_dependency_audit_uses_requirements_flag_when_given(monkeypatch, tmp_path):
    monkeypatch.setattr("supply_chain.vuln_scan.shutil.which", lambda name: "/usr/bin/pip-audit")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n", encoding="utf-8")

    captured_args = {}

    def fake_run(args, capture_output, text, timeout):
        captured_args["args"] = args
        return SimpleNamespace(returncode=0, stdout=json.dumps({"dependencies": []}), stderr="")

    monkeypatch.setattr("supply_chain.vuln_scan.subprocess.run", fake_run)
    run_dependency_audit(requirements_path=requirements)

    assert "--requirement" in captured_args["args"]
    assert str(requirements) in captured_args["args"]
    assert "--local" not in captured_args["args"]


def test_run_dependency_audit_raises_on_unexpected_exit_code(monkeypatch):
    monkeypatch.setattr("supply_chain.vuln_scan.shutil.which", lambda name: "/usr/bin/pip-audit")

    def fake_run(args, capture_output, text, timeout):
        return SimpleNamespace(returncode=3, stdout="", stderr="boom")

    monkeypatch.setattr("supply_chain.vuln_scan.subprocess.run", fake_run)
    with pytest.raises(PipAuditFailed):
        run_dependency_audit()


def test_run_dependency_audit_raises_on_non_json_output(monkeypatch):
    monkeypatch.setattr("supply_chain.vuln_scan.shutil.which", lambda name: "/usr/bin/pip-audit")

    def fake_run(args, capture_output, text, timeout):
        return SimpleNamespace(returncode=0, stdout="not json", stderr="")

    monkeypatch.setattr("supply_chain.vuln_scan.subprocess.run", fake_run)
    with pytest.raises(PipAuditFailed):
        run_dependency_audit()
