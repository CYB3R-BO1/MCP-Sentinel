from proxy.decision import PolicyDecision, allow, deny


def test_allow_factory_sets_allowed_true():
    decision = allow(tool_name="read_file", correlation_id="c1", reason="policy permits read_file")
    assert isinstance(decision, PolicyDecision)
    assert decision.allowed is True
    assert decision.tool_name == "read_file"
    assert decision.correlation_id == "c1"
    assert decision.reason == "policy permits read_file"
    assert decision.rule_id is None
    assert decision.dry_run is False


def test_deny_factory_sets_allowed_false_with_rule_id():
    decision = deny(
        tool_name="fetch_url",
        correlation_id="c2",
        reason="host not in allowlist",
        rule_id="MCP-SENT-002",
    )
    assert decision.allowed is False
    assert decision.rule_id == "MCP-SENT-002"


def test_dry_run_deny_is_marked_but_still_carries_the_would_be_decision():
    decision = deny(
        tool_name="run_command",
        correlation_id="c3",
        reason="tool disabled by policy",
        dry_run=True,
    )
    assert decision.allowed is False
    assert decision.dry_run is True
