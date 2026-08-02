import json

from proxy.cli import main


def test_run_subcommand_delegates_to_stdio_proxy_main(monkeypatch):
    captured = {}

    def fake_stdio_main(argv=None):
        captured["argv"] = argv

    monkeypatch.setattr("proxy.cli.stdio_proxy_main", fake_stdio_main)

    main(["run", "--policy", "custom.yaml", "--audit-log", "custom.jsonl"])

    assert captured["argv"] == ["--policy", "custom.yaml", "--audit-log", "custom.jsonl"]


def test_replay_subcommand_prints_summary_and_exits_zero_when_nothing_changed(tmp_path, capsys):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "version: 1\ndefault_action: deny\ntools:\n  read_file:\n    enabled: true\n", encoding="utf-8"
    )
    audit_log = tmp_path / "audit.jsonl"
    record = {
        "timestamp": "2026-08-02T10:00:00+00:00",
        "correlation_id": "c1",
        "tool_name": "read_file",
        "arguments": {"path": "a.txt"},
        "decision": {
            "allowed": True,
            "tool_name": "read_file",
            "correlation_id": "c1",
            "reason": "policy permits this call",
            "rule_id": None,
            "dry_run": False,
        },
        "latency_seconds": 0.01,
        "injection": None,
    }
    audit_log.write_text(json.dumps(record) + "\n", encoding="utf-8")

    exit_code = main(["replay", "--audit-log", str(audit_log), "--policy", str(policy_file)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "total" in captured.out.lower()
    assert "changed=0" in captured.out.lower()


def test_replay_subcommand_exits_nonzero_when_fail_on_change_and_something_changed(tmp_path, capsys):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        "version: 1\ndefault_action: deny\ntools:\n  run_command:\n    enabled: false\n", encoding="utf-8"
    )
    audit_log = tmp_path / "audit.jsonl"
    record = {
        "timestamp": "2026-08-02T10:00:00+00:00",
        "correlation_id": "c1",
        "tool_name": "run_command",
        "arguments": {"filename": "a.txt"},
        "decision": {
            "allowed": True,
            "tool_name": "run_command",
            "correlation_id": "c1",
            "reason": "policy permits this call",
            "rule_id": None,
            "dry_run": False,
        },
        "latency_seconds": 0.01,
        "injection": None,
    }
    audit_log.write_text(json.dumps(record) + "\n", encoding="utf-8")

    exit_code = main(
        ["replay", "--audit-log", str(audit_log), "--policy", str(policy_file), "--fail-on-change"]
    )

    assert exit_code == 1


def test_replay_subcommand_json_format(tmp_path, capsys):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: 1\ndefault_action: allow\n", encoding="utf-8")
    audit_log = tmp_path / "audit.jsonl"
    record = {
        "timestamp": "2026-08-02T10:00:00+00:00",
        "correlation_id": "c1",
        "tool_name": "read_file",
        "arguments": {"path": "a.txt"},
        "decision": {
            "allowed": True,
            "tool_name": "read_file",
            "correlation_id": "c1",
            "reason": "ok",
            "rule_id": None,
            "dry_run": False,
        },
        "latency_seconds": 0.01,
        "injection": None,
    }
    audit_log.write_text(json.dumps(record) + "\n", encoding="utf-8")

    exit_code = main(
        ["replay", "--audit-log", str(audit_log), "--policy", str(policy_file), "--format", "json"]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["summary"]["total"] == 1
    assert len(payload["results"]) == 1


def test_missing_audit_log_exits_2(tmp_path, capsys):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: 1\n", encoding="utf-8")

    exit_code = main(
        ["replay", "--audit-log", str(tmp_path / "nope.jsonl"), "--policy", str(policy_file)]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "does not exist" in captured.err.lower() or "not found" in captured.err.lower()
