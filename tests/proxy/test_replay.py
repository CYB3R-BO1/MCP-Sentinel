import json
from pathlib import Path

from proxy.decision import allow, deny
from proxy.policy import Policy, ToolPolicy
from proxy.replay import replay_audit_log


def _write_record(log_path: Path, *, tool_name: str, arguments: dict, decision, timestamp: str) -> None:
    record = {
        "timestamp": timestamp,
        "correlation_id": decision.correlation_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "decision": {
            "allowed": decision.allowed,
            "tool_name": decision.tool_name,
            "correlation_id": decision.correlation_id,
            "reason": decision.reason,
            "rule_id": decision.rule_id,
            "dry_run": decision.dry_run,
        },
        "latency_seconds": 0.01,
        "injection": None,
    }
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def test_replay_reproduces_identical_decision_under_unchanged_policy(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    _write_record(
        log_path,
        tool_name="read_file",
        arguments={"path": "sandbox/files/a.txt"},
        decision=allow(tool_name="read_file", correlation_id="c1", reason="policy permits this call"),
        timestamp="2026-08-02T10:00:00+00:00",
    )
    policy = Policy(default_action="deny", tools={"read_file": ToolPolicy(enabled=True)})

    results = replay_audit_log(log_path, policy)

    assert len(results) == 1
    assert results[0].original_allowed is True
    assert results[0].replayed_allowed is True
    assert results[0].changed is False


def test_replay_flags_a_call_that_would_now_be_blocked(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    _write_record(
        log_path,
        tool_name="run_command",
        arguments={"filename": "a.txt"},
        decision=allow(tool_name="run_command", correlation_id="c1", reason="policy permits this call"),
        timestamp="2026-08-02T10:00:00+00:00",
    )
    tightened_policy = Policy(default_action="deny", tools={"run_command": ToolPolicy(enabled=False)})

    results = replay_audit_log(log_path, tightened_policy)

    assert results[0].original_allowed is True
    assert results[0].replayed_allowed is False
    assert results[0].changed is True


def test_replay_flags_a_call_that_would_now_be_allowed(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    _write_record(
        log_path,
        tool_name="run_command",
        arguments={"filename": "a.txt"},
        decision=deny(tool_name="run_command", correlation_id="c1", reason="tool disabled by policy"),
        timestamp="2026-08-02T10:00:00+00:00",
    )
    loosened_policy = Policy(default_action="deny", tools={"run_command": ToolPolicy(enabled=True)})

    results = replay_audit_log(log_path, loosened_policy)

    assert results[0].original_allowed is False
    assert results[0].replayed_allowed is True
    assert results[0].changed is True


def test_replay_respects_recorded_timestamps_for_rate_limiting(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    policy = Policy(default_action="deny", tools={"read_file": ToolPolicy(enabled=True, max_calls_per_minute=2)})

    for i, ts in enumerate(
        ["2026-08-02T10:00:00+00:00", "2026-08-02T10:00:01+00:00", "2026-08-02T10:00:02+00:00"]
    ):
        _write_record(
            log_path,
            tool_name="read_file",
            arguments={"path": f"sandbox/files/{i}.txt"},
            decision=allow(tool_name="read_file", correlation_id=f"c{i}", reason="policy permits this call"),
            timestamp=ts,
        )

    results = replay_audit_log(log_path, policy)

    assert [r.replayed_allowed for r in results] == [True, True, False]


def test_replay_returns_empty_list_for_empty_log(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text("", encoding="utf-8")
    results = replay_audit_log(log_path, Policy())
    assert results == []


def test_summarize_replay_counts_changed_decisions(tmp_path):
    from proxy.replay import summarize_replay

    log_path = tmp_path / "audit.jsonl"
    _write_record(
        log_path,
        tool_name="run_command",
        arguments={"filename": "a.txt"},
        decision=allow(tool_name="run_command", correlation_id="c1", reason="policy permits this call"),
        timestamp="2026-08-02T10:00:00+00:00",
    )
    _write_record(
        log_path,
        tool_name="read_file",
        arguments={"path": "sandbox/files/a.txt"},
        decision=allow(tool_name="read_file", correlation_id="c2", reason="policy permits this call"),
        timestamp="2026-08-02T10:00:01+00:00",
    )
    tightened_policy = Policy(
        default_action="deny",
        tools={"run_command": ToolPolicy(enabled=False), "read_file": ToolPolicy(enabled=True)},
    )

    results = replay_audit_log(log_path, tightened_policy)
    summary = summarize_replay(results)

    assert summary["total"] == 2
    assert summary["changed"] == 1
    assert summary["newly_blocked"] == 1
    assert summary["newly_allowed"] == 0
