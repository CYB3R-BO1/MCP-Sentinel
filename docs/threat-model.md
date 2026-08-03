# Threat model

The full threat model lives at [`../THREAT_MODEL.md`](../THREAT_MODEL.md) — this page is a short pointer,
not a duplicate, so the two can never drift out of sync.

In short: nine STRIDE-mapped vulnerability classes, each mapped to OWASP Top 10 (where a classic web-app
category applies), OWASP LLM/Agentic Top 10, a MITRE ATT&CK technique (where a real one applies), and either
the static scanner rule that detects it (`MCP-SENT-001` through `MCP-SENT-007`) or the runtime proxy check
that blocks it (`MCP-SENT-008`, `MCP-SENT-009` — the two classes that are runtime decision-loop behaviors,
not static data-flow patterns, and so can't be caught by the scanner at all).

The document also walks a full attack tree — attacker-planted instruction in fetched content →
prompt-injection-to-tool-call chaining → path traversal → secret exfiltrated — run for real, twice: once
unprotected against the raw `vulnerable_target` server, once behind `mcp-sentinel-proxy`. The "protected
mode" section documents a genuinely non-obvious finding: the chain breaks one step earlier than the naive
assumption would predict. See [`THREAT_MODEL.md`](../THREAT_MODEL.md#protected-mode-where-the-runtime-proxy-breaks-this-chain)
for why.
