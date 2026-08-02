from pathlib import Path

from proxy.policy import Policy, load_policy_fail_closed, resolve_tool_policy

_VALID_YAML = """
version: 1
default_action: deny
dry_run: false
max_calls_per_minute: 30
tools:
  read_file:
    enabled: true
    allow_path_prefixes: ["sandbox/files"]
  fetch_url:
    enabled: true
    allow_hosts: ["127.0.0.1", "localhost"]
  query_db:
    enabled: true
    readonly: true
  run_command:
    enabled: false
injection_detection:
  enabled: true
  block_on_detection: true
"""


def test_load_valid_policy(tmp_path: Path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(_VALID_YAML, encoding="utf-8")

    policy, warnings = load_policy_fail_closed(policy_file)

    assert warnings == []
    assert policy.default_action == "deny"
    assert policy.max_calls_per_minute == 30
    assert policy.tools["fetch_url"].allow_hosts == ["127.0.0.1", "localhost"]
    assert policy.tools["run_command"].enabled is False


def test_missing_policy_file_fails_closed(tmp_path: Path):
    policy, warnings = load_policy_fail_closed(tmp_path / "does-not-exist.yaml")

    assert policy.default_action == "deny"
    assert policy.tools == {}
    assert len(warnings) == 1
    assert "does-not-exist.yaml" in warnings[0]


def test_malformed_yaml_fails_closed(tmp_path: Path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("tools: [this is not: valid: yaml:", encoding="utf-8")

    policy, warnings = load_policy_fail_closed(policy_file)

    assert policy.default_action == "deny"
    assert len(warnings) == 1


def test_invalid_schema_fails_closed(tmp_path: Path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("version: 1\ndefault_action: not-a-real-action\n", encoding="utf-8")

    policy, warnings = load_policy_fail_closed(policy_file)

    assert policy.default_action == "deny"
    assert len(warnings) == 1


def test_resolve_tool_policy_falls_back_to_default_action_deny():
    policy = Policy(default_action="deny", tools={})
    resolved = resolve_tool_policy(policy, "some_undeclared_tool")
    assert resolved.enabled is False


def test_resolve_tool_policy_falls_back_to_default_action_allow():
    policy = Policy(default_action="allow", tools={})
    resolved = resolve_tool_policy(policy, "some_undeclared_tool")
    assert resolved.enabled is True


def test_resolve_tool_policy_uses_declared_tool_entry():
    policy = Policy(default_action="deny", tools={"fetch_url": {"enabled": True, "allow_hosts": ["example.com"]}})
    resolved = resolve_tool_policy(policy, "fetch_url")
    assert resolved.enabled is True
    assert resolved.allow_hosts == ["example.com"]
