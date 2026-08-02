import pytest

from taxonomy import TAXONOMY, Severity, get_taxonomy_entry


def test_every_entry_key_matches_its_own_rule_id():
    for rule_id, entry in TAXONOMY.items():
        assert entry.rule_id == rule_id


def test_get_taxonomy_entry_returns_the_matching_entry():
    entry = get_taxonomy_entry("MCP-SENT-004")
    assert entry.title.startswith("Unsanitized tool input reaches a SQL")
    assert entry.threat_model_class == 6


def test_get_taxonomy_entry_raises_key_error_for_unknown_rule_id():
    with pytest.raises(KeyError):
        get_taxonomy_entry("NOT-A-REAL-RULE")


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL >= Severity.CRITICAL
    assert not (Severity.LOW >= Severity.HIGH)
