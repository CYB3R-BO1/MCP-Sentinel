# MCP Sentinel — Threat Model

This threat model maps concrete vulnerability classes present in
`vulnerable_target` (Sentinel's own test fixture and demo target) to
STRIDE, OWASP Top 10 (where a classic web-app category genuinely applies),
the OWASP Top 10 for LLM/Agentic Applications, and MITRE ATT&CK techniques
where a real technique applies. Each row will gain a "Detected by" and
"Blocked by" reference once the static scanner (sub-project 2) and runtime
proxy (sub-project 4) are built — this document is updated in place as
those land, not rewritten.

## STRIDE-mapped vulnerability classes

| # | Vulnerability class | STRIDE | OWASP Top 10 | OWASP LLM/Agentic Top 10 | MITRE ATT&CK | Where it lives |
|---|---|---|---|---|---|---|
| 1 | Overly broad tool permission scopes (no least privilege) | Elevation of Privilege | A01:2021 Broken Access Control | LLM06: Excessive Agency | T1548 Abuse Elevation Control Mechanism | `vulnerable_target/permissions.py` |
| 2 | SSRF-capable fetch tool, no host allowlist | Spoofing, Information Disclosure | A10:2021 Server-Side Request Forgery | LLM06: Excessive Agency | T1090 Proxy / T1018 Remote System Discovery | `vulnerable_target/tools/fetch_url.py` |
| 3 | Prompt-injection-to-tool-call chaining (malicious fetched content triggers unintended tool calls) | Tampering, Elevation of Privilege | — | LLM01: Prompt Injection | T1204 User Execution (analog: agent executes attacker-supplied instruction) | `vulnerable_target/agent.py` |
| 4 | Insecure tool output handling (results fed back into model context unsanitized) | Tampering | — | LLM01: Prompt Injection, LLM05: Improper Output Handling | T1565 Data Manipulation | `vulnerable_target/agent.py` |
| 5 | Missing input validation on tool arguments — path traversal | Tampering, Information Disclosure | A01:2021 Broken Access Control | LLM06: Excessive Agency | T1005 Data from Local System | `vulnerable_target/tools/read_file.py` |
| 6 | Missing input validation on tool arguments — SQL injection | Tampering, Information Disclosure | A03:2021 Injection | LLM06: Excessive Agency | T1213 Data from Information Repositories | `vulnerable_target/tools/query_db.py` |
| 7 | Missing input validation on tool arguments — shell/command injection | Tampering, Elevation of Privilege | A03:2021 Injection | LLM06: Excessive Agency | T1059 Command and Scripting Interpreter | `vulnerable_target/tools/run_command.py` |

Note: class #7's shell-injection tests (`tests/vulnerable_target/test_run_command.py`) require a POSIX shell and are skipped on native Windows — run them in Docker, Linux, or WSL for full coverage.

## Attack tree: prompt-injection-to-exfiltration chain

This is the flagship end-to-end scenario used in the README before/after
demo (see `vulnerable_target/scenarios/prompt_injection_chaining.py`).

```
Goal: Exfiltrate a secret file outside the agent's intended sandbox
├── 1. Attacker plants an instruction inside content the agent will fetch
│      (mock "public" HTTP endpoint returns a page containing a fake
│      "SYSTEM:" directive)
├── 2. Agent calls fetch_url on attacker-influenced content [Class 2: SSRF-
│      capable fetch, no allowlist — the tool will fetch anything]
├── 3. Tool output (including the planted directive) is fed back into the
│      agent's decision loop without sanitization [Class 4: insecure output
│      handling]
├── 4. Agent's decision loop naively treats embedded "SYSTEM:" text as an
│      instruction and issues a new, unintended tool call
│      [Class 3: prompt-injection-to-tool-call chaining]
├── 5. The new tool call is read_file with a traversal path
│      [Class 5: missing input validation — path traversal]
└── 6. Secret content outside the sandbox is read and returned in the
       agent's final answer -> exfiltration succeeds
```

Once the runtime proxy (sub-project 4) exists, this same attack tree is
re-run in "protected mode" and the point in the chain where policy
enforcement breaks it is documented directly under this section.

## Non-goals

See `docs/superpowers/specs/2026-08-02-mcp-sentinel-design.md` section 4 for
the full non-goals list (no multi-language scanning, no real network
egress, no distributed policy sync, no eBPF-level enforcement).
