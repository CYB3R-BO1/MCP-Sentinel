from taxonomy.models import Severity, TaxonomyEntry

TAXONOMY: dict[str, TaxonomyEntry] = {
    "MCP-SENT-001": TaxonomyEntry(
        rule_id="MCP-SENT-001",
        title="Excessive tool permission scope",
        stride=("Elevation of Privilege",),
        owasp_top_10="A01:2021 Broken Access Control",
        owasp_llm_top_10=("LLM06: Excessive Agency",),
        mitre_attack=("T1548 Abuse Elevation Control Mechanism",),
        default_severity=Severity.MEDIUM,
        threat_model_class=1,
    ),
    "MCP-SENT-002": TaxonomyEntry(
        rule_id="MCP-SENT-002",
        title="SSRF-capable network fetch with no host allowlist",
        stride=("Spoofing", "Information Disclosure"),
        owasp_top_10="A10:2021 Server-Side Request Forgery",
        owasp_llm_top_10=("LLM06: Excessive Agency",),
        mitre_attack=("T1090 Proxy", "T1018 Remote System Discovery"),
        default_severity=Severity.HIGH,
        threat_model_class=2,
    ),
    "MCP-SENT-003": TaxonomyEntry(
        rule_id="MCP-SENT-003",
        title="Unsanitized tool input reaches a filesystem path sink (path traversal)",
        stride=("Tampering", "Information Disclosure"),
        owasp_top_10="A01:2021 Broken Access Control",
        owasp_llm_top_10=("LLM06: Excessive Agency",),
        mitre_attack=("T1005 Data from Local System",),
        default_severity=Severity.HIGH,
        threat_model_class=5,
    ),
    "MCP-SENT-004": TaxonomyEntry(
        rule_id="MCP-SENT-004",
        title="Unsanitized tool input reaches a SQL execution sink (SQL injection)",
        stride=("Tampering", "Information Disclosure"),
        owasp_top_10="A03:2021 Injection",
        owasp_llm_top_10=("LLM06: Excessive Agency",),
        mitre_attack=("T1213 Data from Information Repositories",),
        default_severity=Severity.CRITICAL,
        threat_model_class=6,
    ),
    "MCP-SENT-005": TaxonomyEntry(
        rule_id="MCP-SENT-005",
        title="Unsanitized tool input reaches a shell execution sink (command injection)",
        stride=("Tampering", "Elevation of Privilege"),
        owasp_top_10="A03:2021 Injection",
        owasp_llm_top_10=("LLM06: Excessive Agency",),
        mitre_attack=("T1059 Command and Scripting Interpreter",),
        default_severity=Severity.CRITICAL,
        threat_model_class=7,
    ),
    "MCP-SENT-006": TaxonomyEntry(
        rule_id="MCP-SENT-006",
        title="Tool endpoints with no rate limiting or authentication",
        stride=("Denial of Service", "Spoofing"),
        owasp_top_10="A04:2021 Insecure Design",
        owasp_llm_top_10=("LLM04: Model Denial of Service", "LLM06: Excessive Agency"),
        mitre_attack=("T1499 Endpoint Denial of Service",),
        default_severity=Severity.MEDIUM,
        threat_model_class=8,
    ),
    "MCP-SENT-007": TaxonomyEntry(
        rule_id="MCP-SENT-007",
        title="Tool description contains embedded instruction-like text (weaponizable injection vector)",
        stride=("Tampering",),
        owasp_top_10=None,
        owasp_llm_top_10=("LLM01: Prompt Injection",),
        mitre_attack=("T1204 User Execution",),
        default_severity=Severity.MEDIUM,
        threat_model_class=9,
    ),
}


def get_taxonomy_entry(rule_id: str) -> TaxonomyEntry:
    try:
        return TAXONOMY[rule_id]
    except KeyError:
        raise KeyError(
            f"Unknown taxonomy rule_id {rule_id!r}; every scanner rule must "
            "have a matching entry in taxonomy.registry.TAXONOMY"
        ) from None
