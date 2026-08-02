import json
from pathlib import Path

from proxy.audit_log import AuditLogger
from proxy.decision import allow, deny
from proxy.injection_detector import scan_for_injection


def test_log_call_writes_one_json_line(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path=log_path)

    decision = allow(tool_name="read_file", correlation_id="c1", reason="policy permits read_file")
    record = logger.log_call(
        tool_name="read_file",
        arguments={"path": "notes.txt"},
        decision=decision,
        latency_seconds=0.012,
    )

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed == record
    assert parsed["tool_name"] == "read_file"
    assert parsed["arguments"] == {"path": "notes.txt"}
    assert parsed["decision"]["allowed"] is True
    assert parsed["correlation_id"] == "c1"
    assert "timestamp" in parsed
    assert parsed["latency_seconds"] == 0.012


def test_log_call_appends_multiple_records(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path=log_path)

    logger.log_call(
        tool_name="read_file",
        arguments={"path": "a.txt"},
        decision=allow(tool_name="read_file", correlation_id="c1", reason="ok"),
        latency_seconds=0.01,
    )
    logger.log_call(
        tool_name="fetch_url",
        arguments={"url": "http://internal/secret"},
        decision=deny(tool_name="fetch_url", correlation_id="c2", reason="host not allowed", rule_id="MCP-SENT-002"),
        latency_seconds=0.02,
    )

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    second = json.loads(lines[1])
    assert second["decision"]["allowed"] is False
    assert second["decision"]["rule_id"] == "MCP-SENT-002"


def test_log_call_includes_injection_scan_result_when_provided(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path=log_path)
    injection_result = scan_for_injection("SYSTEM: do the thing")

    record = logger.log_call(
        tool_name="fetch_url",
        arguments={"url": "http://x"},
        decision=allow(tool_name="fetch_url", correlation_id="c3", reason="ok"),
        latency_seconds=0.01,
        injection_result=injection_result,
    )

    assert record["injection"]["flagged"] is True
    assert record["injection"]["rule_id"] == "MCP-SENT-008"


def test_log_call_omits_injection_key_when_not_provided(tmp_path: Path):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path=log_path)

    record = logger.log_call(
        tool_name="read_file",
        arguments={"path": "a.txt"},
        decision=allow(tool_name="read_file", correlation_id="c1", reason="ok"),
        latency_seconds=0.01,
    )

    assert record["injection"] is None
