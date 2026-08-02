import json

from scanner.findings import Finding
from scanner.output.sarif import findings_to_sarif
from taxonomy import TAXONOMY, Severity


def test_sarif_output_is_json_serializable_with_required_top_level_shape():
    finding = Finding(
        rule_id="MCP-SENT-005",
        severity=Severity.CRITICAL,
        message="Command injection",
        file_path="tools/run_command.py",
        line=14,
        column=5,
    )
    report = findings_to_sarif([finding])
    json.dumps(report)  # must not raise

    assert report["version"] == "2.1.0"
    assert report["$schema"].startswith("https://")
    assert len(report["runs"]) == 1

    run = report["runs"][0]
    assert run["tool"]["driver"]["name"] == "MCP Sentinel"
    rule_ids_declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rule_ids_declared == set(TAXONOMY.keys())


def test_every_result_ruleid_is_declared_and_location_fields_are_well_formed():
    finding = Finding(
        rule_id="MCP-SENT-004",
        severity=Severity.CRITICAL,
        message="SQL injection",
        file_path="tools/query_db.py",
        line=10,
        column=13,
    )
    report = findings_to_sarif([finding])
    run = report["runs"][0]
    declared_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}

    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] in declared_ids
    assert result["level"] == "error"
    assert result["message"]["text"] == "SQL injection"

    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "tools/query_db.py"
    assert isinstance(location["region"]["startLine"], int) and location["region"]["startLine"] >= 1
    assert isinstance(location["region"]["startColumn"], int) and location["region"]["startColumn"] >= 1


def test_severity_to_sarif_level_mapping():
    findings = [
        Finding(rule_id="MCP-SENT-001", severity=Severity.MEDIUM, message="m", file_path="a.py", line=1, column=1),
        Finding(rule_id="MCP-SENT-002", severity=Severity.HIGH, message="h", file_path="a.py", line=2, column=1),
        Finding(rule_id="MCP-SENT-007", severity=Severity.MEDIUM, message="m2", file_path="a.py", line=3, column=1),
    ]
    report = findings_to_sarif(findings)
    levels = {r["message"]["text"]: r["level"] for r in report["runs"][0]["results"]}
    assert levels["m"] == "warning"
    assert levels["h"] == "error"


def test_empty_findings_still_produces_valid_sarif_with_declared_rules():
    report = findings_to_sarif([])
    assert report["runs"][0]["results"] == []
    assert len(report["runs"][0]["tool"]["driver"]["rules"]) == len(TAXONOMY)
