import json

from scanner.findings import Finding
from scanner.output.json_output import findings_to_json
from taxonomy import Severity


def test_json_output_is_json_serializable_and_has_expected_shape():
    finding = Finding(
        rule_id="MCP-SENT-004",
        severity=Severity.CRITICAL,
        message="SQL injection",
        file_path="tools/query_db.py",
        line=10,
        column=13,
        taint_trace=("step1", "step2"),
    )
    report = findings_to_json([finding], "src/vulnerable_target")

    serialized = json.dumps(report)
    round_tripped = json.loads(serialized)
    assert round_tripped == report

    assert report["schema_version"] == "1.0"
    assert report["scan_root"] == "src/vulnerable_target"
    assert report["summary"]["total"] == 1
    assert report["summary"]["by_severity"]["critical"] == 1
    assert report["summary"]["by_severity"]["low"] == 0

    entry = report["findings"][0]
    assert entry["rule_id"] == "MCP-SENT-004"
    assert entry["severity"] == "critical"
    assert entry["file"] == "tools/query_db.py"
    assert entry["line"] == 10
    assert entry["column"] == 13
    assert entry["taint_trace"] == ["step1", "step2"]
    assert entry["taxonomy"]["owasp_top_10"] == "A03:2021 Injection"
    assert "LLM06: Excessive Agency" in entry["taxonomy"]["owasp_llm_top_10"]
    assert entry["taxonomy"]["threat_model_class"] == 6


def test_empty_findings_still_produces_valid_summary():
    report = findings_to_json([], "root")
    assert report["summary"]["total"] == 0
    assert report["findings"] == []
