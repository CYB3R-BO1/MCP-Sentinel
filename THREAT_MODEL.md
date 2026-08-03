# MCP Sentinel — Threat Model

This threat model maps concrete vulnerability classes present in
`vulnerable_target` (Sentinel's own test fixture and demo target) to
STRIDE, OWASP Top 10 (where a classic web-app category genuinely applies),
the OWASP Top 10 for LLM/Agentic Applications, and MITRE ATT&CK techniques
where a real technique applies. The "Detected by" column names the static
scanner rule (see `src/scanner/`, taxonomy in `src/taxonomy/registry.py`)
that catches each class, where one exists; "Blocked by" is filled in once
the runtime proxy (sub-project 4) lands — this document is updated in
place as that happens, not rewritten.

## STRIDE-mapped vulnerability classes

| # | Vulnerability class | STRIDE | OWASP Top 10 | OWASP LLM/Agentic Top 10 | MITRE ATT&CK | Where it lives | Detected by |
|---|---|---|---|---|---|---|---|
| 1 | Overly broad tool permission scopes (no least privilege) | Elevation of Privilege | A01:2021 Broken Access Control | LLM06: Excessive Agency | T1548 Abuse Elevation Control Mechanism | `vulnerable_target/permissions.py` | `MCP-SENT-001` (structural: scope vs. declared purpose) |
| 2 | SSRF-capable fetch tool, no host allowlist | Spoofing, Information Disclosure | A10:2021 Server-Side Request Forgery | LLM06: Excessive Agency | T1090 Proxy / T1018 Remote System Discovery | `vulnerable_target/tools/fetch_url.py` | `MCP-SENT-002` (taint: tainted URL to HTTP fetch) |
| 3 | Prompt-injection-to-tool-call chaining (malicious fetched content triggers unintended tool calls) | Tampering, Elevation of Privilege | — | LLM01: Prompt Injection | T1204 User Execution (analog: agent executes attacker-supplied instruction) | `vulnerable_target/agent.py` | Not statically detectable — this is a runtime decision-loop behavior, not a data-flow-to-sink pattern. `MCP-SENT-008` (runtime: proxy's injection detector scans tool output before it re-enters model context, see `src/proxy/injection_detector.py`) |
| 4 | Insecure tool output handling (results fed back into model context unsanitized) | Tampering | — | LLM01: Prompt Injection, LLM05: Improper Output Handling | T1565 Data Manipulation | `vulnerable_target/agent.py` | Not statically detectable (same reason as class #3). `MCP-SENT-009` (runtime: same injection-detector pass, flagged before the tainted output is forwarded) |
| 5 | Missing input validation on tool arguments — path traversal | Tampering, Information Disclosure | A01:2021 Broken Access Control | LLM06: Excessive Agency | T1005 Data from Local System | `vulnerable_target/tools/read_file.py` | `MCP-SENT-003` (taint: tainted path to filesystem sink) |
| 6 | Missing input validation on tool arguments — SQL injection | Tampering, Information Disclosure | A03:2021 Injection | LLM06: Excessive Agency | T1213 Data from Information Repositories | `vulnerable_target/tools/query_db.py` | `MCP-SENT-004` (taint: tainted string to `.execute()`) |
| 7 | Missing input validation on tool arguments — shell/command injection | Tampering, Elevation of Privilege | A03:2021 Injection | LLM06: Excessive Agency | T1059 Command and Scripting Interpreter | `vulnerable_target/tools/run_command.py` | `MCP-SENT-005` (taint: tainted string to `shell=True`/`os.system`) |
| 8 | Tool endpoints with no rate limiting or authentication | Denial of Service, Spoofing | A04:2021 Insecure Design | LLM04: Model Denial of Service, LLM06: Excessive Agency | T1499 Endpoint Denial of Service | `vulnerable_target/server.py` | `MCP-SENT-006` (structural: file registers `.tool()` endpoints with no rate-limit/auth token present) |
| 9 | Tool description weaponized as a prompt-injection vector | Tampering | — | LLM01: Prompt Injection | T1204 User Execution | Not present in `vulnerable_target` (its tool docstrings are clean by design — this class needs a deliberately malicious fixture, see `tests/scanner/test_structural_tool_description_injection.py`) | `MCP-SENT-007` (structural: instruction-like phrasing in a `.tool()`-decorated docstring) |

Notes:
- Class #7's shell-injection tests (`tests/vulnerable_target/test_run_command.py`) require a POSIX shell and are skipped on native Windows — run them in Docker, Linux, or WSL for full coverage.
- The scanner's taint engine (classes #2, #5, #6, #7) is genuinely interprocedural: it follows a tainted value from a tool's parameter through a helper-function call into a different file before it reaches the sink, not just same-function pattern matching. See `src/scanner/taint/engine.py` and `tests/scanner/test_engine_interprocedural.py`.

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

### Protected mode: where the runtime proxy breaks this chain

`tests/proxy/test_protected_mode_demo.py` re-runs this exact scenario
against `mcp-sentinel-proxy` (`src/proxy/stdio_proxy.py`) in place of the
raw `vulnerable_target/server.py`, using `default_policy.yaml`. The chain
breaks at **step 3**, not step 4 or 5 as might be assumed: the proxy's
injection detector (`MCP-SENT-009`) scans `fetch_url`'s output *before*
returning it to the agent, flags the embedded "SYSTEM:" directive, and
blocks the result outright (`injection_detection.block_on_detection:
true`). The agent's decision loop never sees the planted instruction, so
it never issues the follow-up `read_file` call at all — class #3
(prompt-injection-to-tool-call chaining, `MCP-SENT-008`) never gets a
chance to fire, because class #4 (insecure output handling) is caught
first.

This also means the proxy's per-tool containment on `read_file` (the
`..`-traversal block enforcing class #5) is defense-in-depth
here, not the layer that actually stops this particular attack — it *is*
exercised directly, and proven to block a traversal path on its own, in
`tests/proxy/test_stdio_proxy_integration.py::test_path_traversal_read_is_blocked_for_real`.

## Non-goals

See `docs/superpowers/specs/2026-08-02-mcp-sentinel-design.md` section 4 for
the full non-goals list (no multi-language scanning, no real network
egress, no distributed policy sync, no eBPF-level enforcement).
